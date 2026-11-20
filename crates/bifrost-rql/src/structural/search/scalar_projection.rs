//! Semantic projections of call rows. No site presentation is constructed here.

use std::cell::OnceCell;

use super::call_binding::{semantic_model_origin_label, semantic_model_proof_label};
use super::dispatch::{DispatchCompleteness, DispatchProof};
use super::results::checked_row_scalar;
use super::*;

/// Borrows the native scalar surface of one row. A demanded literal can keep
/// one file's facts alive until this view drops, never a whole-pass facts memo.
pub(super) struct PipelineScalarRow<'a> {
    analyzer: &'a dyn IAnalyzer,
    row: &'a PipelineRow,
    other: Option<CodeQueryResultItem>,
    facts: OnceCell<Option<Arc<FileFacts>>>,
    declaration_ids: OnceCell<(String, Option<String>)>,
    target_id: OnceCell<Option<String>>,
}

impl<'a> PipelineScalarRow<'a> {
    pub(super) fn new(analyzer: &'a dyn IAnalyzer, row: &'a PipelineRow) -> Self {
        let other = match &row.value {
            PipelineValue::CallSite(_)
            | PipelineValue::ExpressionSite(_)
            | PipelineValue::CallArgument(_)
            | PipelineValue::CallBinding(_) => None,
            _ => {
                // A scalar does not consume presentation of an earlier step.
                let mut terminal = row.clone();
                terminal.traces.clear();
                Some(
                    render_pipeline_item(
                        analyzer,
                        terminal,
                        CodeQueryResultDetail::Full,
                        &mut PipelineRenderCache::default(),
                    )
                    .expect("non-site scalar projection has no site admission"),
                )
            }
        };
        Self {
            analyzer,
            row,
            other,
            facts: OnceCell::new(),
            declaration_ids: OnceCell::new(),
            target_id: OnceCell::new(),
        }
    }

    pub(super) fn domain(&self) -> DetailedCodeQueryDomain {
        match &self.row.value {
            PipelineValue::CallSite(_) => DetailedCodeQueryDomain::CallSite,
            PipelineValue::ExpressionSite(_) => DetailedCodeQueryDomain::ExpressionSite,
            PipelineValue::CallArgument(_) => DetailedCodeQueryDomain::CallArgument,
            PipelineValue::CallBinding(_) => DetailedCodeQueryDomain::CallBinding,
            _ => self
                .other
                .as_ref()
                .expect("other row was projected")
                .value
                .detailed_domain(),
        }
    }

    pub(super) fn fields(&self) -> &'static [CodeQueryRowField] {
        self.domain().row_fields()
    }

    pub(super) fn field(
        &self,
        name: &str,
    ) -> Result<Option<CodeQueryRowScalarRef<'_>>, CodeQueryRowFieldError> {
        if let Some(other) = &self.other {
            return other.value.row().field(name);
        }
        checked_row_scalar(self.domain(), name, || {
            if let PipelineValue::CallBinding(value) = &self.row.value
                && name == "conversion"
                && let Some(reason) = value.row().conversion_reason
            {
                return Err(CodeQueryRowFieldUnknownReason::CallConversion(reason));
            }
            Ok(self.project(name))
        })
    }

    fn source_range(&self) -> Option<(&ProjectFile, &Range)> {
        match &self.row.value {
            PipelineValue::CallSite(site) => Some((&site.0.file, &site.0.range)),
            PipelineValue::ExpressionSite(site) => Some((&site.call_site.0.file, &site.range)),
            PipelineValue::CallArgument(value) => Some((
                &value.shape.report.outcome.file,
                &value.shape.report.arguments[value.argument_index].range,
            )),
            PipelineValue::CallBinding(value) => Some((value.file(), &value.row().range)),
            _ => None,
        }
    }

    /// Final projection uses exactly the sources admitted by preparation.
    pub(super) fn display_range(&self, cache: &mut PipelineRenderCache) -> Option<CodeQueryRange> {
        match self.source_range() {
            Some((file, range)) => Some(render_source_range(self.analyzer, file, range, cache)),
            None => self
                .other
                .as_ref()
                .expect("other row was projected")
                .value
                .display_range(),
        }
    }

    /// Predicates precede source preparation. Their diagnostic identity borrows
    /// selected facts when available and never hydrates text just for columns.
    pub(super) fn predicate_range(&self) -> Option<CodeQueryRange> {
        let Some((file, range)) = self.source_range() else {
            return self
                .other
                .as_ref()
                .expect("other row was projected")
                .value
                .display_range();
        };
        let held = match &self.row.value {
            PipelineValue::CallArgument(value) => value.shape.facts.as_deref(),
            PipelineValue::CallBinding(value) => value.site.shape.facts.as_deref(),
            _ => None,
        }
        .or_else(|| {
            self.row
                .traces
                .iter()
                .find(|trace| &trace.seed.file == file)
                .map(|trace| trace.seed.facts.as_ref())
        });
        Some(held.map_or(
            CodeQueryRange {
                start_line: range.start_line,
                start_column: 1,
                end_line: range.end_line,
                end_column: 1,
            },
            |facts| {
                range_for_span(
                    facts,
                    Span {
                        start_byte: range.start_byte,
                        end_byte: range.end_byte,
                    },
                )
            },
        ))
    }

    fn file_facts(&self, file: &ProjectFile, held: Option<&Arc<FileFacts>>) -> Option<&FileFacts> {
        self.facts
            .get_or_init(|| {
                held.cloned().or_else(|| {
                    let language = crate::analyzer::common::language_for_file(file);
                    self.analyzer
                        .structural_fact_providers()
                        .into_iter()
                        .find(|provider| provider.structural_language() == language)
                        .and_then(|provider| provider.structural_facts(file))
                })
            })
            .as_deref()
    }

    fn argument_literal(&self, shape: &CallShapeValue, argument_index: usize) -> Option<&str> {
        let argument = &shape.report.arguments[argument_index];
        let node = argument.node?;
        self.file_facts(&shape.report.outcome.file, shape.facts.as_ref())?
            .node(node)
            .string_value
            .as_deref()
    }

    fn binding_literal(&self, value: &CallBindingValue) -> Option<&str> {
        let row = value.row();
        if let Some(argument_id) = &row.argument_id {
            let index = value
                .site
                .shape
                .report
                .arguments
                .iter()
                .position(|argument| &argument.id == argument_id)
                .expect("binding names an argument of its own shape");
            return self.argument_literal(&value.site.shape, index);
        }
        if row.terminal
            || row.binding_kind
                != Some(crate::analyzer::usages::call_binding::CallBindingKind::Receiver)
        {
            return None;
        }
        self.file_facts(value.file(), value.site.shape.facts.as_ref())?
            .nodes()
            .iter()
            .rev()
            .find(|node| {
                node.span().start_byte == row.range.start_byte
                    && node.span().end_byte == row.range.end_byte
            })?
            .string_value
            .as_deref()
    }

    fn project(&self, name: &str) -> Option<CodeQueryRowScalarRef<'_>> {
        use CodeQueryRowScalarRef as Scalar;
        match &self.row.value {
            PipelineValue::CallSite(site) => match name {
                "caller_id" | "callee_id" => {
                    let (caller, callee) = self.declaration_ids.get_or_init(|| {
                        let caller =
                            declaration_value_for_unit(self.analyzer, &site.0.caller, site.0.range)
                                .declaration_id();
                        let callee = site
                            .6
                            .as_ref()
                            .filter(|target| {
                                target.boundary_kind.is_some() || target.reason.is_some()
                            })
                            .is_none()
                            .then(|| {
                                declaration_value_for_unit(
                                    self.analyzer,
                                    &site.0.callee,
                                    site.0.callee_range,
                                )
                                .declaration_id()
                            });
                        (caller, callee)
                    });
                    if name == "caller_id" {
                        Some(Scalar::DeclarationIdentity(caller))
                    } else {
                        callee.as_deref().map(Scalar::DeclarationIdentity)
                    }
                }
                "site_id" => site.4.as_deref().map(Scalar::StableId),
                "program_point_id" => site.3.as_deref().map(Scalar::StableId),
                "target_id" => site
                    .6
                    .as_ref()
                    .and_then(|target| target.target_id.as_deref())
                    .map(Scalar::StableId),
                "target_fq_name" => site
                    .6
                    .as_ref()
                    .and_then(|target| target.target_fq_name.as_deref())
                    .map(Scalar::String),
                "boundary_kind" => site
                    .6
                    .as_ref()
                    .and_then(|target| target.boundary_kind)
                    .map(Scalar::ConstrainedEnum),
                "target_reason" => site
                    .6
                    .as_ref()
                    .and_then(|target| target.reason.as_deref())
                    .map(Scalar::String),
                "completeness" => Some(Scalar::ConstrainedEnum(
                    site.6
                        .as_ref()
                        .map_or("complete", |target| target.completeness),
                )),
                "coverage" => Some(Scalar::ConstrainedEnum(
                    site.6
                        .as_ref()
                        .map_or("exhaustive", |target| target.coverage),
                )),
                "call_kind" => Some(Scalar::ConstrainedEnum(call_syntax_kind_label(site.0.kind))),
                "proof" => Some(Scalar::ConstrainedEnum(usage_proof_label(site.0.proof))),
                "receiver_kind" => Some(Scalar::ConstrainedEnum(site.5.receiver_kind)),
                "argument_identity" => site
                    .5
                    .argument_identities
                    .first()
                    .and_then(Option::as_deref)
                    .map(Scalar::StableId),
                "caller_parameter_identity" => site
                    .5
                    .caller_parameter_identities
                    .first()
                    .and_then(Option::as_deref)
                    .map(Scalar::StableId),
                _ => unreachable!("registered call-site scalar {name}"),
            },
            PipelineValue::ExpressionSite(site) => match (&site.input, name) {
                (ExpressionInput::Receiver, "input_kind") => {
                    Some(Scalar::ConstrainedEnum("receiver"))
                }
                (ExpressionInput::Parameter { .. }, "input_kind") => {
                    Some(Scalar::ConstrainedEnum("parameter"))
                }
                (ExpressionInput::Parameter { index, .. }, "parameter_index") => {
                    Some(Scalar::Integer(*index as u64))
                }
                (ExpressionInput::Parameter { name, .. }, "parameter_name") => {
                    name.as_deref().map(Scalar::String)
                }
                (ExpressionInput::Receiver, "parameter_index" | "parameter_name") => None,
                _ => unreachable!("registered expression-site scalar {name}"),
            },
            PipelineValue::CallArgument(value) => {
                let argument = &value.shape.report.arguments[value.argument_index];
                match name {
                    "id" => Some(Scalar::StableId(&argument.id)),
                    "group_id" => Some(Scalar::StableId(&argument.group_id)),
                    "site_id" => Some(Scalar::StableId(&value.shape.report.outcome.site_id)),
                    "argument_index" => Some(Scalar::Integer(argument.argument_index as u64)),
                    "name" => argument.name.as_deref().map(Scalar::String),
                    "literal_value" => self
                        .argument_literal(&value.shape, value.argument_index)
                        .map(Scalar::String),
                    "spread" => Some(Scalar::Boolean(argument.spread)),
                    _ => unreachable!("registered call-argument scalar {name}"),
                }
            }
            PipelineValue::CallBinding(value) => self.binding_field(value, name),
            _ => unreachable!("other scalar rows use their existing projector"),
        }
    }

    fn binding_field<'b>(
        &'b self,
        value: &'b CallBindingValue,
        name: &str,
    ) -> Option<CodeQueryRowScalarRef<'b>> {
        use CodeQueryRowScalarRef as Scalar;
        let site = &value.site;
        let row = value.row();
        match name {
            "id" => Some(Scalar::StableId(&row.id)),
            "site_id" => Some(Scalar::StableId(&row.site_id)),
            "site_ast_id" => Some(Scalar::StableId(&site.report.site_ast_id)),
            "program_point_id" => site.program_point_id.as_deref().map(Scalar::StableId),
            "group_id" => row.group_id.as_deref().map(Scalar::StableId),
            "argument_id" => row.argument_id.as_deref().map(Scalar::StableId),
            "binding_id" => site
                .binding_ids
                .get(value.index)
                .and_then(Option::as_deref)
                .map(Scalar::StableId),
            "literal_value" => self.binding_literal(value).map(Scalar::String),
            "path_identity" => site
                .path_identities
                .get(value.index)
                .and_then(Option::as_deref)
                .map(Scalar::String),
            "target_id" => self
                .target_id
                .get_or_init(|| site.target.as_ref().map(DeclarationValue::declaration_id))
                .as_deref()
                .map(Scalar::DeclarationIdentity),
            "declared_target_id" => site.declared_target_id.as_deref().map(Scalar::StableId),
            "semantic_target_id" => site.semantic_target_id.as_deref().map(Scalar::StableId),
            "model_callable_id" => site.model_callable_id.as_deref().map(Scalar::StableId),
            "formal_layout_id" => site.formal_layout_id.as_deref().map(Scalar::StableId),
            "target_origin" => site.target_origin.map(Scalar::ConstrainedEnum),
            "dispatch_outcome" => Some(Scalar::ConstrainedEnum(site.dispatch.status.label())),
            "dispatch_coverage" => Some(Scalar::ConstrainedEnum(
                site.dispatch.coverage_status.label(),
            )),
            "dispatch_proof" => site
                .dispatch
                .proof
                .map(DispatchProof::label)
                .map(Scalar::ConstrainedEnum),
            "dispatch_completeness" => site
                .dispatch
                .completeness
                .map(DispatchCompleteness::label)
                .map(Scalar::ConstrainedEnum),
            "dispatch_target_count" => Some(Scalar::Integer(site.dispatch.target_count as u64)),
            "dispatch_targets_truncated" => Some(Scalar::Boolean(site.dispatch.targets_truncated)),
            "selector_exact" => Some(Scalar::Boolean(site.selector.exact)),
            "selector_proof" => site.selector.tier.map(Scalar::ConstrainedEnum),
            "selector_summary_id" => site.selector.summary_id.as_deref().map(Scalar::String),
            "selector_summary_model_id" => site
                .selector
                .summary_model_id
                .as_deref()
                .map(Scalar::String),
            "signature_id" => site.signature_id.as_deref().map(Scalar::StableId),
            "model_id" => site.model_id.as_deref().map(Scalar::String),
            "receiver_type_id" => site.receiver_type_id.as_deref().map(Scalar::StableId),
            "pack_id" => site.pack_id.as_deref().map(Scalar::String),
            "actual_index" => row.actual_index.map(|index| Scalar::Integer(index as u64)),
            "actual_name" => row.actual_name.as_deref().map(Scalar::String),
            "formal_index" => row.formal_index.map(|index| Scalar::Integer(index as u64)),
            "formal_name" => row.formal_name.as_deref().map(Scalar::String),
            "binding_kind" => row
                .binding_kind
                .map(|kind| Scalar::ConstrainedEnum(kind.label())),
            "conversion" => row.conversion.as_deref().map(Scalar::ConstrainedEnum),
            "conversion_reason" => row
                .conversion_reason
                .map(|reason| Scalar::ConstrainedEnum(reason.label())),
            "conversion_status" => Some(Scalar::ConstrainedEnum(
                if row.argument_id.is_none()
                    || matches!(
                        row.binding_kind,
                        Some(
                            crate::analyzer::usages::call_binding::CallBindingKind::Receiver
                                | crate::analyzer::usages::call_binding::CallBindingKind::Implicit
                        )
                    )
                {
                    "not_applicable"
                } else if row.conversion_reason.is_some() {
                    "unknown"
                } else {
                    "proven"
                },
            )),
            "mapping" => Some(Scalar::ConstrainedEnum(row.mapping.label())),
            "reason" => row
                .reason
                .map(|reason| Scalar::ConstrainedEnum(reason.label())),
            "coverage" => Some(Scalar::ConstrainedEnum(site.report.coverage.label())),
            "actual_count" => Some(Scalar::Integer(site.report.actual_count as u64)),
            "bound_count" => Some(Scalar::Integer(site.report.bound_count as u64)),
            "terminal" => Some(Scalar::Boolean(row.terminal)),
            _ => {
                let (provenance, field) =
                    if let Some(field) = name.strip_prefix("selector_summary_") {
                        (site.selector.summary_provenance.as_deref(), field)
                    } else {
                        (
                            site.semantic_model_provenance.as_deref(),
                            name.strip_prefix("model_")
                                .expect("registered binding provenance field"),
                        )
                    };
                provenance_field(provenance, field)
            }
        }
    }
}

fn provenance_field<'a>(
    provenance: Option<&'a crate::analyzer::semantic_model::SemanticModelProvenance>,
    field: &str,
) -> Option<CodeQueryRowScalarRef<'a>> {
    use CodeQueryRowScalarRef as Scalar;
    match field {
        "pack_id" => provenance.map(|value| Scalar::String(&value.pack_id)),
        "active_set_hash" => provenance.map(|value| Scalar::String(&value.active_model_set_hash)),
        "pack_digest" => provenance.map(|value| Scalar::String(&value.pack_digest)),
        "pack_version" => provenance.map(|value| Scalar::String(&value.pack_version)),
        "record_id" => provenance.map(|value| Scalar::String(&value.record_id)),
        "activation_status" => provenance.map(|value| Scalar::String(&value.activation.status)),
        "activation_reason" => provenance.map(|value| Scalar::String(&value.activation.reason)),
        "activation_source_kind" => {
            provenance.map(|value| Scalar::String(&value.activation.source_kind))
        }
        "activation_source_id" => {
            provenance.map(|value| Scalar::String(&value.activation.source_id))
        }
        "origin" => provenance
            .map(|value| Scalar::ConstrainedEnum(semantic_model_origin_label(value.origin))),
        "proof" | "model_proof" => {
            provenance.map(|value| Scalar::ConstrainedEnum(semantic_model_proof_label(value.proof)))
        }
        "completeness" => {
            provenance.map(|value| Scalar::ConstrainedEnum(value.completeness.label()))
        }
        "ambiguous" => provenance.map(|value| Scalar::Boolean(value.ambiguous)),
        "producer" => provenance.map(|value| Scalar::String(&value.producer)),
        "producer_version" => provenance.map(|value| Scalar::String(&value.producer_version)),
        _ => unreachable!("registered binding provenance field {field}"),
    }
}

/// Identity-only provenance for call rows, without constructing a site payload.
pub(super) fn project_call_argument_ref(
    analyzer: &dyn IAnalyzer,
    value: &CallArgumentValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let argument = &value.shape.report.arguments[value.argument_index];
    let file = &value.shape.report.outcome.file;
    CodeQueryResultRef::CallArgument {
        id: argument.id.clone(),
        group_id: argument.group_id.clone(),
        path: rel_path_string(file),
        range: render_source_range(analyzer, file, &argument.range, cache),
        argument_index: argument.argument_index,
    }
}

pub(super) fn project_call_binding_ref(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    let site = &value.site;
    let provenance = site.semantic_model_provenance.as_deref();
    CodeQueryResultRef::CallBinding {
        id: row.id.clone(),
        site_id: row.site_id.clone(),
        path: rel_path_string(value.file()),
        range: render_source_range(analyzer, value.file(), &row.range, cache),
        semantic_target_id: site.semantic_target_id.clone(),
        target_origin: site.target_origin,
        model_id: site.model_id.clone(),
        receiver_type_id: site.receiver_type_id.clone(),
        pack_id: site.pack_id.clone(),
        model_record_id: provenance.map(|value| value.record_id.clone()),
        model_activation_status: provenance.map(|value| value.activation.status.clone()),
        model_activation_source_kind: provenance.map(|value| value.activation.source_kind.clone()),
        model_activation_source_id: provenance.map(|value| value.activation.source_id.clone()),
        model_origin: provenance.map(|value| semantic_model_origin_label(value.origin)),
        model_proof: provenance.map(|value| semantic_model_proof_label(value.proof)),
        model_completeness: provenance.map(|value| value.completeness.label()),
        binding_kind: row.binding_kind.map(|kind| kind.label()),
        mapping: row.mapping.label(),
        coverage: site.report.coverage.label(),
    }
}

/// Live selected-row facts; these types never enter the persisted unit shape.
#[derive(Debug, Clone, Serialize)]
pub struct SelectorCallSiteFacts {
    pub proof: &'static str,
    pub completeness: &'static str,
    pub coverage: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub struct SelectorExpressionSiteFacts {
    pub input_kind: &'static str,
    pub parameter_index: Option<usize>,
    pub parameter_name: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SelectorCallArgumentFacts {
    pub id: String,
    pub group_id: String,
    pub site_id: String,
    pub argument_index: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct SelectorCallBindingFacts {
    pub has_source_target: bool,
    pub id: String,
    pub site_id: String,
    pub site_ast_id: String,
    pub program_point_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub group_id: Option<String>,
    pub argument_id: Option<String>,
    pub binding_id: Option<String>,
    pub path_identity: Option<String>,
    pub declared_target_id: Option<String>,
    pub semantic_target_id: Option<String>,
    pub target_origin: Option<&'static str>,
    pub dispatch_outcome: &'static str,
    pub dispatch_coverage: &'static str,
    pub dispatch_proof: Option<&'static str>,
    pub dispatch_completeness: Option<&'static str>,
    pub dispatch_target_count: usize,
    pub dispatch_targets_truncated: bool,
    pub selector_exact: bool,
    pub selector_proof: Option<&'static str>,
    pub selector_summary_id: Option<String>,
    pub selector_summary_model_id: Option<String>,
    pub selector_summary_pack_id: Option<String>,
    pub selector_summary_active_set_hash: Option<String>,
    pub selector_summary_pack_digest: Option<String>,
    pub selector_summary_pack_version: Option<String>,
    pub selector_summary_record_id: Option<String>,
    pub selector_summary_origin: Option<&'static str>,
    pub selector_summary_model_proof: Option<&'static str>,
    pub selector_summary_completeness: Option<&'static str>,
    pub selector_summary_producer: Option<String>,
    pub selector_summary_producer_version: Option<String>,
    pub signature_id: Option<String>,
    pub model_callable_id: Option<String>,
    pub formal_layout_id: Option<String>,
    pub model_id: Option<String>,
    pub receiver_type_id: Option<String>,
    pub pack_id: Option<String>,
    pub model_active_set_hash: Option<String>,
    pub model_pack_digest: Option<String>,
    pub model_pack_version: Option<String>,
    pub model_record_id: Option<String>,
    pub model_activation_status: Option<String>,
    pub model_activation_reason: Option<String>,
    pub model_activation_source_kind: Option<String>,
    pub model_activation_source_id: Option<String>,
    pub model_origin: Option<&'static str>,
    pub model_proof: Option<&'static str>,
    pub model_completeness: Option<&'static str>,
    pub model_ambiguous: Option<bool>,
    pub model_producer: Option<String>,
    pub model_producer_version: Option<String>,
    pub actual_index: Option<usize>,
    pub actual_name: Option<String>,
    pub formal_index: Option<usize>,
    pub formal_name: Option<String>,
    pub binding_kind: Option<&'static str>,
    pub conversion: Option<String>,
    pub conversion_status: &'static str,
    pub conversion_reason: Option<crate::analyzer::usages::call_conversion::ConversionUnknown>,
    pub mapping: &'static str,
    pub reason: Option<&'static str>,
    pub coverage: &'static str,
    pub actual_count: usize,
    pub bound_count: usize,
    pub terminal: bool,
}

pub type SelectorResultValue = QueryResultValue<
    Box<SelectorCallSiteFacts>,
    Box<SelectorExpressionSiteFacts>,
    Box<SelectorCallArgumentFacts>,
    Box<SelectorCallBindingFacts>,
>;
pub type SelectorResultItem = QueryResultItem<SelectorResultValue>;
pub type SelectorQueryResult = QueryResult<SelectorResultItem>;
pub type DetailedSelectorResult = DetailedQueryResult<SelectorResultItem>;

pub(super) fn project_selector_row(
    analyzer: &dyn IAnalyzer,
    row: &PipelineRow,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
    completion: &CodeQueryCompletion,
    provenance: Vec<CodeQueryProvenance>,
) -> (UnitRowItem, SelectorResultItem) {
    if matches!(
        &row.value,
        PipelineValue::CallSite(_)
            | PipelineValue::ExpressionSite(_)
            | PipelineValue::CallArgument(_)
            | PipelineValue::CallBinding(_)
    ) {
        let item = UnitRowItem::project_native(analyzer, row, detail, &provenance, cache);
        let value = project_selector_value(analyzer, row, cache);
        return (
            item,
            SelectorResultItem {
                value,
                provenance,
                provenance_truncated: row.provenance_truncated,
                row_projection: row.row_projection.clone(),
            },
        );
    }
    let mut terminal = row.clone();
    terminal.traces.clear();
    let mut presented = render_pipeline_item(analyzer, terminal, detail, cache)
        .expect("non-site row projection has no site admission");
    presented.provenance = provenance;
    if let CodeQueryResultValue::FlowEndpoint { value } = &mut presented.value {
        results::cap_flow_status_for_completion(value, completion);
    }
    let item = UnitRowItem::project(&presented);
    (
        item,
        SelectorResultItem {
            value: presented.value.into_selector_value(),
            provenance: presented.provenance,
            provenance_truncated: presented.provenance_truncated,
            row_projection: presented.row_projection,
        },
    )
}

fn project_selector_value(
    analyzer: &dyn IAnalyzer,
    row: &PipelineRow,
    cache: &mut PipelineRenderCache,
) -> SelectorResultValue {
    match &row.value {
        PipelineValue::CallSite(site) => SelectorResultValue::CallSite {
            value: Box::new(SelectorCallSiteFacts {
                proof: usage_proof_label(site.0.proof),
                completeness: site
                    .6
                    .as_ref()
                    .map_or("complete", |target| target.completeness),
                coverage: site
                    .6
                    .as_ref()
                    .map_or("exhaustive", |target| target.coverage),
            }),
        },
        PipelineValue::ExpressionSite(site) => {
            let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
            SelectorResultValue::ExpressionSite {
                value: Box::new(SelectorExpressionSiteFacts {
                    input_kind,
                    parameter_index,
                    parameter_name,
                }),
            }
        }
        PipelineValue::CallArgument(value) => {
            let argument = &value.shape.report.arguments[value.argument_index];
            SelectorResultValue::CallArgument {
                value: Box::new(SelectorCallArgumentFacts {
                    id: argument.id.clone(),
                    group_id: argument.group_id.clone(),
                    site_id: value.shape.report.outcome.site_id.clone(),
                    argument_index: argument.argument_index,
                }),
            }
        }
        PipelineValue::CallBinding(value) => SelectorResultValue::CallBinding {
            value: Box::new(project_selector_binding(analyzer, value, cache)),
        },
        _ => unreachable!("only site-bearing payloads need native selection facts"),
    }
}

fn project_selector_binding(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    cache: &mut PipelineRenderCache,
) -> SelectorCallBindingFacts {
    let report = &value.site.report;
    let row = value.row();
    let provenance = value.site.semantic_model_provenance.as_deref();
    let summary = value.site.selector.summary_provenance.as_deref();
    let binding_id = value.site.binding_ids.get(value.index).cloned().flatten();
    let conversion_applicable = row.argument_id.is_some()
        && !matches!(
            row.binding_kind,
            Some(
                crate::analyzer::usages::call_binding::CallBindingKind::Receiver
                    | crate::analyzer::usages::call_binding::CallBindingKind::Implicit
            )
        );
    let conversion_reason = row.conversion_reason;
    assert!(
        !conversion_applicable || row.conversion.is_some() != conversion_reason.is_some(),
        "each ordinary actual has either a conversion proof or typed unknown"
    );
    SelectorCallBindingFacts {
        has_source_target: value.site.target.is_some(),
        id: row.id.clone(),
        site_id: row.site_id.clone(),
        site_ast_id: report.site_ast_id.clone(),
        program_point_id: value.site.program_point_id.clone(),
        path: rel_path_string(&report.file),
        language: crate::analyzer::common::language_for_file(&report.file).config_label(),
        range: render_source_range(analyzer, &report.file, &row.range, cache),
        group_id: row.group_id.clone(),
        argument_id: row.argument_id.clone(),
        binding_id,
        path_identity: value
            .site
            .path_identities
            .get(value.index)
            .cloned()
            .flatten(),
        declared_target_id: value.site.declared_target_id.clone(),
        semantic_target_id: value.site.semantic_target_id.clone(),
        target_origin: value.site.target_origin,
        dispatch_outcome: value.site.dispatch.status.label(),
        dispatch_coverage: value.site.dispatch.coverage_status.label(),
        dispatch_proof: value.site.dispatch.proof.map(DispatchProof::label),
        dispatch_completeness: value
            .site
            .dispatch
            .completeness
            .map(DispatchCompleteness::label),
        dispatch_target_count: value.site.dispatch.target_count,
        dispatch_targets_truncated: value.site.dispatch.targets_truncated,
        selector_exact: value.site.selector.exact,
        selector_proof: value.site.selector.tier,
        selector_summary_id: value.site.selector.summary_id.clone(),
        selector_summary_model_id: value.site.selector.summary_model_id.clone(),
        selector_summary_pack_id: summary.map(|value| value.pack_id.clone()),
        selector_summary_active_set_hash: summary.map(|value| value.active_model_set_hash.clone()),
        selector_summary_pack_digest: summary.map(|value| value.pack_digest.clone()),
        selector_summary_pack_version: summary.map(|value| value.pack_version.clone()),
        selector_summary_record_id: summary.map(|value| value.record_id.clone()),
        selector_summary_origin: summary.map(|value| semantic_model_origin_label(value.origin)),
        selector_summary_model_proof: summary.map(|value| semantic_model_proof_label(value.proof)),
        selector_summary_completeness: summary.map(|value| value.completeness.label()),
        selector_summary_producer: summary.map(|value| value.producer.clone()),
        selector_summary_producer_version: summary.map(|value| value.producer_version.clone()),
        signature_id: value.site.signature_id.clone(),
        model_callable_id: value.site.model_callable_id.clone(),
        formal_layout_id: value.site.formal_layout_id.clone(),
        model_id: value.site.model_id.clone(),
        receiver_type_id: value.site.receiver_type_id.clone(),
        pack_id: value.site.pack_id.clone(),
        model_active_set_hash: provenance.map(|value| value.active_model_set_hash.clone()),
        model_pack_digest: provenance.map(|value| value.pack_digest.clone()),
        model_pack_version: provenance.map(|value| value.pack_version.clone()),
        model_record_id: provenance.map(|value| value.record_id.clone()),
        model_activation_status: provenance.map(|value| value.activation.status.clone()),
        model_activation_reason: provenance.map(|value| value.activation.reason.clone()),
        model_activation_source_kind: provenance.map(|value| value.activation.source_kind.clone()),
        model_activation_source_id: provenance.map(|value| value.activation.source_id.clone()),
        model_origin: provenance.map(|value| semantic_model_origin_label(value.origin)),
        model_proof: provenance.map(|value| semantic_model_proof_label(value.proof)),
        model_completeness: provenance.map(|value| value.completeness.label()),
        model_ambiguous: provenance.map(|value| value.ambiguous),
        model_producer: provenance.map(|value| value.producer.clone()),
        model_producer_version: provenance.map(|value| value.producer_version.clone()),
        actual_index: row.actual_index,
        actual_name: row.actual_name.clone(),
        formal_index: row.formal_index,
        formal_name: row.formal_name.clone(),
        binding_kind: row.binding_kind.map(|kind| kind.label()),
        conversion: row.conversion.clone(),
        conversion_status: if !conversion_applicable {
            "not_applicable"
        } else if conversion_reason.is_some() {
            "unknown"
        } else {
            "proven"
        },
        conversion_reason,
        mapping: row.mapping.label(),
        reason: row.reason.map(|reason| reason.label()),
        coverage: report.coverage.label(),
        actual_count: report.actual_count,
        bound_count: report.bound_count,
        terminal: row.terminal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::structural::search::tests::inline_project::InlineTestProject;

    struct CompareNativeScalarSurface;

    impl QueryRowsFinalizer for CompareNativeScalarSurface {
        type Output = Vec<UnitRowKey>;

        fn unexecuted(self, result: DetailedCodeQueryResult) -> Self::Output {
            panic!("fixture did not execute: {result:?}")
        }

        fn finish(
            self,
            rows: ExecutedQueryRows<'_>,
            mut context: QueryFinalizationContext<'_, '_>,
        ) -> Self::Output {
            let analyzer = context.analyzer;
            let mut prepared = prepare_native_rows(rows, &mut context);
            let native_rows = std::mem::take(&mut prepared.native);
            assert!(native_rows.len() >= 2, "both actual calls must execute");
            if matches!(native_rows[0].value, PipelineValue::CallArgument(_)) {
                assert!(native_rows.iter().any(|row| matches!(&row.value,
                    PipelineValue::CallArgument(value) if value.shape.report.arguments[value.argument_index].name.is_none())),
                    "a positional argument must exercise genuine optional absence");
                assert!(native_rows.iter().any(|row| matches!(&row.value,
                    PipelineValue::CallArgument(value) if value.shape.report.arguments[value.argument_index].name.is_some())),
                    "a named argument must exercise the known optional value");
            }
            for detail in CodeQueryResultDetail::ALL {
                // Every window.take() consumes one demanded projection. A
                // second detail must acquire its own real demanded window.
                prepared.render_cache.presentation = None;
                prepared.render_cache.presentation = Some(
                    presentation::PresentationWindow::prepare(
                        analyzer,
                        &native_rows,
                        prepared._owner.clone(),
                        &prepared.render_cache,
                        context.cancellation,
                    )
                    .expect("ordinary fixture admission"),
                );
                for native in &native_rows {
                    let scalars = PipelineScalarRow::new(analyzer, native);
                    let presented = render_pipeline_item(
                        analyzer,
                        native.clone(),
                        detail,
                        &mut prepared.render_cache,
                    )
                    .expect("ordinary fixture presentation");
                    assert_eq!(scalars.domain(), presented.value.detailed_domain());
                    if detail == CodeQueryResultDetail::Full {
                        // The semantic scalar API deliberately stays complete.
                        for field in scalars.fields() {
                            assert_eq!(
                                scalars.field(field.name),
                                presented.value.row().field(field.name),
                                "{}.{}",
                                scalars.domain().label(),
                                field.name
                            );
                        }
                        assert_eq!(
                            scalars.field("unregistered_field"),
                            presented.value.row().field("unregistered_field")
                        );
                    }
                    let native_item = UnitRowItem::project_native(
                        analyzer,
                        native,
                        detail,
                        &presented.provenance,
                        &mut prepared.render_cache,
                    );
                    assert_eq!(
                        native_item,
                        UnitRowItem::project(&presented),
                        "persisted unit surface: {} {detail:?}",
                        scalars.domain().label()
                    );
                    let output_name = |source: &'static str| {
                        native
                            .row_projection
                            .iter()
                            .find(|column| column.source == source)
                            .map_or(source, |column| column.name.as_str())
                    };
                    let optional_id_sources: &[&str] = match &native.value {
                        PipelineValue::CallSite(_) => &["caller_id", "callee_id"],
                        PipelineValue::CallBinding(_) => &["target_id"],
                        _ => &[],
                    };
                    for &source in optional_id_sources {
                        assert!(
                            matches!(scalars.field(source), Ok(Some(CodeQueryRowScalarRef::DeclarationIdentity(id))) if !id.is_empty()),
                            "Full source identity must be positive, not absent parity: {source}"
                        );
                        let value = native_item
                            .field(output_name(source))
                            .expect("selected optional alias stays registered");
                        assert_eq!(value.is_some(), detail == CodeQueryResultDetail::Full);
                    }
                    if let PipelineValue::CallArgument(value) = &native.value {
                        let argument = &value.shape.report.arguments[value.argument_index];
                        let actual = native_item
                            .field(output_name("name"))
                            .expect("selected optional argument-name alias stays registered");
                        assert_eq!(
                            actual,
                            argument.name.as_deref().map(CodeQueryRowScalarRef::String)
                        );
                    }
                    if matches!(native.value, PipelineValue::CallSite(_)) {
                        assert!(
                            native_item.field(output_name("proof")).unwrap().is_some(),
                            "known proof aliased callee_id must survive Compact"
                        );
                    }
                    if matches!(native.value, PipelineValue::CallBinding(_)) {
                        assert!(
                            native_item.field(output_name("id")).unwrap().is_some(),
                            "stable row id aliased target_id must survive Compact"
                        );
                        assert!(
                            native_item
                                .field(output_name("conversion"))
                                .unwrap_err()
                                .unknown_reason()
                                .is_some(),
                            "unavailable conversion stays typed under aliases and both details"
                        );
                    }
                    let (file, _) = scalars.source_range().expect("site row");
                    for entry in [
                        Some(RetainedSource::BudgetRefused),
                        Some(RetainedSource::Conflicting),
                        Some(RetainedSource::Unavailable),
                        None,
                    ] {
                        let mut refused = PipelineRenderCache::default();
                        if let Some(entry) = entry {
                            refused.retain_loaded_source(file, entry);
                        }
                        refused.seal_source_loads();
                        let projected = UnitRowItem::project_native(
                            analyzer,
                            native,
                            detail,
                            &presented.provenance,
                            &mut refused,
                        );
                        let range = projected.range.expect("site range");
                        assert_eq!(
                            (range.start_column, range.end_column),
                            (1, 1),
                            "prepared source refusal controls unit coordinates"
                        );
                        assert!(
                            !matches!(refused.sources.get(file), Some(RetainedSource::Retained(_))),
                            "unit projection must not hydrate a refused or sealed source"
                        );
                    }
                }
            }
            native_rows
                .iter()
                .map(|row| unit_row_key(&row.value.key()))
                .collect()
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14068: native units bypassed sealed sources and Compact identity/provenance metadata"
    )]
    fn native_call_scalars_preserve_registered_fields_and_unit_projection() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "def sink(value):\n    return value\ndef use():\n    sink(\"h\\u00e9llo\\nworld\")\n    sink(value=\"named\")\n")
            .file("unrelated.py", "def unrelated():\n    return 0\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
        let mut files = workspace.analyzer().analyzed_files();
        files.sort_by(seed_file_order);
        assert_eq!(
            files.len(),
            2,
            "the real API comparison partitions seed files"
        );
        for (domain, source) in [
            (
                DetailedCodeQueryDomain::CallSite,
                "(call-sites-from (enclosing-decl (function (name \"use\"))))",
            ),
            (
                DetailedCodeQueryDomain::ExpressionSite,
                "(call-input :parameter-index 0 (call-sites-from (enclosing-decl (function (name \"use\")))))",
            ),
            (
                DetailedCodeQueryDomain::CallArgument,
                "(call-arguments (call-argument-groups (call-shape (call :callee (name \"sink\")))))",
            ),
            (
                DetailedCodeQueryDomain::CallBinding,
                "(call-bindings (call-shape (call :callee (name \"sink\"))))",
            ),
        ] {
            let columns = domain
                .row_fields()
                .iter()
                .map(|field| {
                    // Swap both identity names; also place known evidence under an
                    // identity-looking output name to reject output-name filtering.
                    let name = match (domain, field.name) {
                        (DetailedCodeQueryDomain::CallSite, "caller_id") => "target_id".to_string(),
                        (DetailedCodeQueryDomain::CallSite, "target_id") => "caller_id".to_string(),
                        (DetailedCodeQueryDomain::CallSite, "proof") => "callee_id".to_string(),
                        (DetailedCodeQueryDomain::CallBinding, "target_id") => "id".to_string(),
                        (DetailedCodeQueryDomain::CallBinding, "id") => "target_id".to_string(),
                        _ => format!("selected_{}", field.name),
                    };
                    (field.name, format!("({} {name})", field.name))
                })
                .collect::<Vec<_>>();
            // Honor the existing 32-column query-authoring bound. Every
            // registered source is still aliased across these batches; keep
            // the non-vacuous identity/unknown oracles present in every batch.
            let (required, remaining): (Vec<_>, Vec<_>) =
                columns.into_iter().partition(|(field, _)| {
                    matches!(
                        (domain, *field),
                        (
                            DetailedCodeQueryDomain::CallSite,
                            "caller_id" | "callee_id" | "target_id" | "proof"
                        ) | (DetailedCodeQueryDomain::CallArgument, "name")
                            | (
                                DetailedCodeQueryDomain::CallBinding,
                                "id" | "target_id" | "conversion"
                            )
                    )
                });
            let projected = remaining.chunks(32 - required.len()).map(|chunk| {
                let columns = required
                    .iter()
                    .chain(chunk)
                    .map(|(_, column)| column.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("(project :columns ({columns}) {source})")
            });
            for source in std::iter::once(source.to_string()).chain(projected) {
                let mut query = CodeQuery::from_sexp(&source).expect("query");
                let expected_keys = {
                    let read_scope = AnalyzerQueryScope::new(workspace.analyzer());
                    execute_query_rows_with_finalizer(
                        workspace.analyzer(),
                        read_scope.token(),
                        None,
                        Some(&workspace),
                        Some((&flow).into()),
                        None,
                        0,
                        &query,
                        CodeQueryExecutionLimits::default(),
                        None,
                        None,
                        false,
                        UnionExecutionStrategy::Auto,
                        CODE_QUERY_SCHEDULER_WORKERS,
                        eager_structural_access_mode(),
                        OccurrenceDerivationOptions::IDENTITY_ONLY,
                        None,
                        None,
                        None,
                        CodeQueryExecutionScope::whole_workspace(),
                        None,
                        None,
                        EdgeTraversalCache::default(),
                        CompareNativeScalarSurface,
                    )
                };
                let mut expected_keys = expected_keys
                    .iter()
                    .map(|key| serde_json::to_string(key).unwrap())
                    .collect::<Vec<_>>();
                expected_keys.sort();
                for detail in CodeQueryResultDetail::ALL {
                    query.result_detail = detail;
                    let whole = execute_code_query_detailed_eager_index_workspace(
                        &workspace,
                        &flow,
                        &query,
                        CodeQueryExecutionLimits::default(),
                        None,
                    );
                    assert!(
                        whole.result.results.len() >= 2,
                        "nonempty whole: {source}: {:?}",
                        whole.result
                    );
                    assert!(
                        whole
                            .result
                            .results
                            .iter()
                            .all(|row| row.value.detailed_domain() == domain),
                        "each authored family must execute its actual domain"
                    );
                    assert_eq!(
                        whole.result.completion(),
                        CodeQueryCompletion::Complete,
                        "whole must be complete: {:?}",
                        whole.result.diagnostics
                    );
                    let units = files
                        .iter()
                        .map(|file| {
                            let unit = execute_code_query_unit(
                                workspace.analyzer(),
                                &flow,
                                Some(&workspace),
                                &query,
                                CodeQueryExecutionLimits::default(),
                                None,
                                CodeQueryExecutionScope::for_seed_files(
                                    std::slice::from_ref(file),
                                    &files,
                                ),
                            );
                            assert_eq!(
                                unit.completion,
                                CodeQueryCompletion::Complete,
                                "unit must be complete: {:?}",
                                unit.diagnostics
                            );
                            assert!(!unit.truncated);
                            unit
                        })
                        .collect::<Vec<_>>();
                    let mut actual_keys = units
                        .iter()
                        .flat_map(|unit| &unit.rows)
                        .map(|row| serde_json::to_string(&row.key).unwrap())
                        .collect::<Vec<_>>();
                    actual_keys.sort();
                    assert_eq!(
                        actual_keys, expected_keys,
                        "native dedup identity: {source} {detail:?}"
                    );
                    let merged = merge_unit_rows(&query, units);
                    assert_eq!(merged.completion(), whole.result.completion());
                    assert_eq!(merged.truncated, whole.result.truncated);
                    assert_eq!(
                        merged.items,
                        whole
                            .result
                            .results
                            .iter()
                            .map(UnitRowItem::project)
                            .collect::<Vec<_>>(),
                        "generic unit API vs whole: {source} {detail:?}"
                    );
                    assert_eq!(
                        merged.detailed_evidence(project.root()),
                        whole.evidence,
                        "exact aligned provenance/evidence: {source} {detail:?}"
                    );
                }
            }
        }
    }
}
