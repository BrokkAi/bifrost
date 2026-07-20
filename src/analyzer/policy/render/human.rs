//! Deterministic, terminal-safe human policy-report rendering.

use std::fmt;
use std::io::{self, Write};

use super::super::{
    CategoryPredicate, CertaintyReason, ClassificationProvenance, CvssAssessment,
    CvssAssessmentProvenance, CvssAssessmentVariant, CvssComponentResult, CvssEvidenceBasis,
    CvssEvidenceScope, CvssMetricEvidence, CvssNomenclature, CvssSeverity, CvssSystemScope,
    CvssUnscoredReason, CvssVersion, DirectoryScope, EndpointDefinitionSchemaResolution,
    EndpointObservationPhase, EndpointOrigin, EndpointRole, EndpointTaintSemantics, EvidenceRef,
    FindingCertainty, FindingClassification, FindingCompleteness, FindingIdentityStability,
    FindingIncompleteReason, FindingSeverity, MatchFindingAnchor, MatchResultDomain,
    OrganizationalRiskAssessment, PolicyAnalysisType, PolicyCapability, PolicyDiagnosticImpact,
    PolicyDiagnosticSeverity, PolicyEndpointBinding, PolicyFailureReason, PolicyFinding,
    PolicyFindingEvidence, PolicyIncompleteReason, PolicyLevel, PolicyLocationRelationship,
    PolicyMessageSpec, PolicyOverlayScope, PolicyQueryProof, PolicyQueryProvenance,
    PolicyQueryResultRef, PolicyReportDocument, PolicyRuleDescriptor, PolicyRun,
    PolicyRunCompletion, PolicySemanticEvent, PolicySeveritySpec, PolicySourceLocation,
    ProofMetadata, ProofReason, ProofState, ResolvedEndpointDependency, ResolvedEndpointIdentity,
    ResolvedEndpointManifestEntry, ResolvedMatchDirectoryManifest, ResolvedPrecedenceEdge,
    ResolvedTypestateTerminal, SchemaVersionOrigin, SchemaVersionResolution,
    StableSemanticIdentity, TaintSourceEvidence, TaintSystemEntry, TaintTrustBoundary,
    TypestateViolationEvidence, WitnessStepKind,
};
use super::{
    BoundedWriter, PolicyRenderError, ensure_supported_schema, map_io_error,
    should_escape_text_character,
};

/// Human output options for schema version 1.
///
/// Schema version 1 intentionally has no color mode. Output is plain text and
/// byte-for-byte stable whether it is written to a terminal, pipe, or file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HumanRenderOptions;

/// Write a deterministic, terminal-safe summary of a canonical report.
pub fn write_policy_human<W: Write>(
    report: &PolicyReportDocument,
    _options: &HumanRenderOptions,
    output: W,
    max_serialized_bytes: usize,
) -> Result<u64, PolicyRenderError> {
    ensure_supported_schema(report)?;
    let mut output = BoundedWriter::new(output, max_serialized_bytes);

    write_schema_inference_notes(&mut output, report)?;
    for diagnostic in report.diagnostics() {
        write!(
            output,
            "report diagnostic: [{}] {}: {}",
            diagnostic_severity(diagnostic.severity()),
            report_diagnostic_code(diagnostic.code()),
            escape_terminal_text(diagnostic.message()),
        )
        .map_err(map_io_error)?;
        if let Some(source) = diagnostic.source() {
            write!(output, " ({})", escape_terminal_text(source.as_str())).map_err(map_io_error)?;
            if let Some(range) = diagnostic.byte_range() {
                write!(output, ":{}-{}", range.start(), range.end()).map_err(map_io_error)?;
            }
        }
        writeln!(output).map_err(map_io_error)?;
        for related in diagnostic.related() {
            writeln!(
                output,
                "  related: {}:{}-{}: {}",
                escape_terminal_text(related.source.as_str()),
                related.range.start,
                related.range.end,
                escape_terminal_text(&related.message),
            )
            .map_err(map_io_error)?;
        }
    }
    if report.diagnostics_truncated() {
        writeln!(
            output,
            "report diagnostics truncated: at least {} omitted; worst severity {}",
            report.omitted_diagnostics_lower_bound(),
            report
                .worst_omitted_diagnostic_severity()
                .map_or("unknown", diagnostic_severity),
        )
        .map_err(map_io_error)?;
    }

    for run in report.runs() {
        for finding in run.findings() {
            write_finding(&mut output, finding)?;
        }
        write_run_diagnostics(&mut output, run)?;
        if !run.completion().is_complete() || run.diagnostics_truncated() {
            let rule = report
                .rules()
                .iter()
                .find(|rule| {
                    rule.policy_id() == run.policy_id()
                        && rule.policy_hash() == run.policy_hash()
                        && rule.analysis_type() == run.analysis_type()
                })
                .ok_or(PolicyRenderError::InvalidCanonicalReport {
                    detail: "policy run has no matching rule descriptor",
                })?;
            write_run_completion(&mut output, run, rule.name())?;
        }
    }

    // Keep each explicit-schema finding stanza anchored by its clickable
    // location. Descriptor details follow findings rather than preceding the
    // first one, while zero-finding reports still retain the complete rule
    // contract before their summary.
    for rule in report.rules() {
        write_rule_detail(&mut output, rule)?;
    }

    write_summary(&mut output, report)?;
    output.flush().map_err(map_io_error)?;
    Ok(output.bytes_written())
}

fn write_finding<W: Write>(
    output: &mut BoundedWriter<W>,
    finding: &PolicyFinding,
) -> Result<(), PolicyRenderError> {
    write_location(output, finding.primary()).map_err(map_io_error)?;
    writeln!(
        output,
        ": [{}] {}: {}",
        finding_severity(finding.severity()),
        escape_terminal_text(finding.policy_id().as_str()),
        escape_terminal_text(finding.message()),
    )
    .map_err(map_io_error)?;
    writeln!(
        output,
        "  finding: {} ({})",
        finding.id(),
        identity_stability(finding.identity_stability()),
    )
    .map_err(map_io_error)?;
    writeln!(
        output,
        "  analysis: {} ({}, {})",
        analysis_type(finding.analysis_type()),
        certainty(finding.certainty()),
        completeness(finding.completeness()),
    )
    .map_err(map_io_error)?;
    if let FindingCompleteness::Partial { reasons } = finding.completeness() {
        write!(output, "  finding incomplete:").map_err(map_io_error)?;
        for reason in reasons {
            write!(output, " {}", finding_incomplete_reason(*reason)).map_err(map_io_error)?;
        }
        writeln!(output).map_err(map_io_error)?;
    }
    write_evidence_summary(output, finding)?;
    write_evidence_detail(output, finding.evidence())?;
    write_certainty_detail(output, finding.certainty())?;
    write_proof_detail(output, finding.proof())?;
    write_classification(output, finding.classification())?;

    for related in finding.related() {
        write!(
            output,
            "  related {}: ",
            location_relationship(related.relationship())
        )
        .map_err(map_io_error)?;
        write_location(output, related.location()).map_err(map_io_error)?;
        if !related.evidence_refs().is_empty() {
            write!(output, " [evidence").map_err(map_io_error)?;
            for evidence in related.evidence_refs() {
                write!(output, " {}", escape_terminal_text(evidence.as_str()))
                    .map_err(map_io_error)?;
            }
            write!(output, "]").map_err(map_io_error)?;
        }
        writeln!(output).map_err(map_io_error)?;
    }
    if finding.related_truncated() {
        writeln!(
            output,
            "  related locations truncated: at least {} omitted",
            finding.omitted_related_locations_lower_bound(),
        )
        .map_err(map_io_error)?;
    }

    if let Some(risk) = finding.organizational_risk() {
        write_organizational_risk(output, risk)?;
    }

    writeln!(output, "  proof: {}", proof_state(finding.proof().state())).map_err(map_io_error)?;
    for witness in finding.witnesses() {
        writeln!(
            output,
            "  witness {} ({} step{}, {} retained bytes{}):",
            escape_terminal_text(witness.id().as_str()),
            witness.steps().len(),
            plural_suffix(witness.steps().len()),
            witness.retained_bytes(),
            if witness.truncated() {
                ", truncated"
            } else {
                ""
            },
        )
        .map_err(map_io_error)?;
        for step in witness.steps() {
            write!(
                output,
                "    {}: {}",
                witness_step_kind(step.kind()),
                escape_terminal_text(step.label()),
            )
            .map_err(map_io_error)?;
            if let Some(location) = step.location() {
                write!(output, " at ").map_err(map_io_error)?;
                write_location(output, location).map_err(map_io_error)?;
            }
            write_evidence_refs_suffix(output, step.evidence_refs())?;
            writeln!(output).map_err(map_io_error)?;
        }
        if witness.truncated() {
            writeln!(
                output,
                "    at least {} witness step{} omitted",
                witness.omitted_steps_lower_bound(),
                plural_suffix_u64(witness.omitted_steps_lower_bound()),
            )
            .map_err(map_io_error)?;
        }
    }
    if finding.witnesses_truncated() {
        writeln!(
            output,
            "  witnesses truncated: at least {} omitted",
            finding.omitted_witnesses_lower_bound(),
        )
        .map_err(map_io_error)?;
    }
    if finding.evidence_refs_truncated() {
        writeln!(
            output,
            "  evidence references truncated: at least {} omitted",
            finding.omitted_evidence_refs_lower_bound(),
        )
        .map_err(map_io_error)?;
    }

    if let Some(cvss) = finding.cvss() {
        for variant in cvss.variants() {
            let selected = cvss.selected_for_display() == Some(variant.id());
            match variant.assessment() {
                CvssAssessment::Scored {
                    nomenclature,
                    vector,
                    components,
                    ..
                } => {
                    let component = named_cvss_component(components, *nomenclature)?;
                    writeln!(
                        output,
                        "  cvss variant {}{}: {} {:.1} {} {}",
                        variant.id(),
                        if selected { " [selected]" } else { "" },
                        cvss_nomenclature(*nomenclature),
                        component.score(),
                        cvss_severity(component.severity()),
                        escape_terminal_text(vector),
                    )
                    .map_err(map_io_error)?;
                }
                CvssAssessment::Unscored {
                    missing_base_metrics,
                    reasons,
                    ..
                } => {
                    writeln!(
                        output,
                        "  cvss variant {}: unscored ({} missing base metric{}; {} reason{})",
                        variant.id(),
                        missing_base_metrics.len(),
                        plural_suffix(missing_base_metrics.len()),
                        reasons.len(),
                        plural_suffix(reasons.len()),
                    )
                    .map_err(map_io_error)?;
                }
            }
            write_cvss_variant_detail(output, variant)?;
        }
        if let Some(rationale) = cvss.selection_rationale() {
            writeln!(
                output,
                "  cvss selection: {}",
                escape_terminal_text(rationale),
            )
            .map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_schema_inference_notes<W: Write>(
    output: &mut BoundedWriter<W>,
    report: &PolicyReportDocument,
) -> Result<(), PolicyRenderError> {
    for rule in report.rules() {
        let policy_inferred =
            rule.policy_schema().origin == SchemaVersionOrigin::ImplicitCompatible;
        let inferred_rql_versions =
            normalized_inferred_versions(rule.selector_schemas().iter().filter_map(|selector| {
                (selector.resolution().origin == SchemaVersionOrigin::ImplicitCompatible)
                    .then_some(selector.resolution().version)
            }));
        let inferred_endpoint_policy_versions = normalized_inferred_versions(
            rule.endpoint_dependencies().iter().filter_map(|endpoint| {
                let EndpointDefinitionSchemaResolution::PolicyDocument { resolution } =
                    endpoint.definition_schema()
                else {
                    return None;
                };
                (resolution.origin == SchemaVersionOrigin::ImplicitCompatible)
                    .then_some(resolution.version)
            }),
        );
        let inferred_endpoint_rql_versions = normalized_inferred_versions(
            rule.endpoint_dependencies().iter().filter_map(|endpoint| {
                (endpoint.selector_schema().origin == SchemaVersionOrigin::ImplicitCompatible)
                    .then_some(endpoint.selector_schema().version)
            }),
        );

        let mut phrases = Vec::with_capacity(4);
        if policy_inferred {
            phrases.push(("policy schema", vec![rule.policy_schema().version]));
        }
        if !inferred_rql_versions.is_empty() {
            phrases.push(("RQL schema", inferred_rql_versions));
        }
        if !inferred_endpoint_policy_versions.is_empty() {
            phrases.push(("endpoint policy schema", inferred_endpoint_policy_versions));
        }
        if !inferred_endpoint_rql_versions.is_empty() {
            phrases.push(("endpoint RQL schema", inferred_endpoint_rql_versions));
        }
        if phrases.is_empty() {
            continue;
        }

        write!(
            output,
            "note: policy {} inferred ",
            escape_terminal_text(rule.policy_id().as_str()),
        )
        .map_err(map_io_error)?;
        for (index, (label, versions)) in phrases.iter().enumerate() {
            if index > 0 {
                if index + 1 == phrases.len() {
                    write!(output, " and ").map_err(map_io_error)?;
                } else {
                    write!(output, ", ").map_err(map_io_error)?;
                }
            }
            if versions.len() == 1 {
                write!(output, "{label} {}", versions[0]).map_err(map_io_error)?;
            } else {
                write!(output, "{label}s ").map_err(map_io_error)?;
                for (version_index, version) in versions.iter().enumerate() {
                    if version_index > 0 {
                        write!(output, ", ").map_err(map_io_error)?;
                    }
                    write!(output, "{version}").map_err(map_io_error)?;
                }
            }
        }
        writeln!(output).map_err(map_io_error)?;
    }
    Ok(())
}

fn normalized_inferred_versions(values: impl Iterator<Item = u32>) -> Vec<u32> {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn write_rule_detail<W: Write>(
    output: &mut BoundedWriter<W>,
    rule: &PolicyRuleDescriptor,
) -> Result<(), PolicyRenderError> {
    writeln!(
        output,
        "policy rule: {} ({})",
        escape_terminal_text(rule.policy_id().as_str()),
        escape_terminal_text(rule.name()),
    )
    .map_err(map_io_error)?;
    writeln!(output, "  policy hash: {}", rule.policy_hash()).map_err(map_io_error)?;
    writeln!(
        output,
        "  analysis type: {}",
        analysis_type(rule.analysis_type())
    )
    .map_err(map_io_error)?;
    write_schema_resolution(output, "  policy schema", rule.policy_schema())?;
    for selector in rule.selector_schemas() {
        write!(
            output,
            "  selector schema {}: ",
            escape_terminal_text(selector.path().as_str()),
        )
        .map_err(map_io_error)?;
        write_schema_resolution_value(output, selector.resolution())?;
        writeln!(output).map_err(map_io_error)?;
    }
    if rule.endpoint_dependencies().is_empty() {
        writeln!(output, "  endpoint dependencies: none").map_err(map_io_error)?;
    } else {
        for endpoint in rule.endpoint_dependencies() {
            write_endpoint_dependency(output, endpoint)?;
        }
    }
    if rule.match_directory_manifests().is_empty() {
        writeln!(output, "  match directories: none").map_err(map_io_error)?;
    } else {
        for manifest in rule.match_directory_manifests() {
            write_match_directory_manifest(output, manifest)?;
        }
    }
    if rule.precedence_manifest().edges.is_empty() {
        writeln!(output, "  precedence: none").map_err(map_io_error)?;
    } else {
        for edge in &rule.precedence_manifest().edges {
            write_precedence_edge(output, edge)?;
        }
    }
    match rule.message() {
        PolicyMessageSpec::Static { text } => {
            writeln!(output, "  message: static - {}", escape_terminal_text(text),)
                .map_err(map_io_error)?
        }
        PolicyMessageSpec::Generated { .. } => {
            writeln!(output, "  message: generated can_reach").map_err(map_io_error)?;
        }
    }
    write!(output, "  severity: ").map_err(map_io_error)?;
    match rule.severity() {
        PolicySeveritySpec::Fixed { level } => {
            writeln!(output, "fixed {}", policy_level(*level)).map_err(map_io_error)?;
        }
        PolicySeveritySpec::Unrated => {
            writeln!(output, "unrated").map_err(map_io_error)?;
        }
        PolicySeveritySpec::Cvss { when_unscored } => {
            writeln!(
                output,
                "cvss (when unscored: {})",
                finding_severity(*when_unscored),
            )
            .map_err(map_io_error)?;
        }
    }
    if let Some(description) = rule.description() {
        writeln!(
            output,
            "  description: {}",
            escape_terminal_text(description),
        )
        .map_err(map_io_error)?;
    }
    if let Some(help_uri) = rule.help_uri() {
        writeln!(output, "  help: {}", escape_terminal_text(help_uri)).map_err(map_io_error)?;
    }
    write_text_items(output, "  tag", rule.tags().iter().map(String::as_str))
}

fn write_endpoint_dependency<W: Write>(
    output: &mut BoundedWriter<W>,
    endpoint: &ResolvedEndpointDependency,
) -> Result<(), PolicyRenderError> {
    write!(output, "  endpoint dependency: ").map_err(map_io_error)?;
    write_endpoint_identity(output, endpoint.identity())?;
    writeln!(output).map_err(map_io_error)?;
    write!(output, "    definition schema: ").map_err(map_io_error)?;
    write_endpoint_definition_schema(output, endpoint.definition_schema())?;
    writeln!(output).map_err(map_io_error)?;
    write!(
        output,
        "    selector {}: ",
        escape_terminal_text(endpoint.selector_path().as_str()),
    )
    .map_err(map_io_error)?;
    write_schema_resolution_value(output, endpoint.selector_schema())?;
    writeln!(output).map_err(map_io_error)?;
    writeln!(output, "    semantic hash: {}", endpoint.semantic_hash()).map_err(map_io_error)?;
    writeln!(
        output,
        "    analysis projection hash: {}",
        endpoint.analysis_projection_hash(),
    )
    .map_err(map_io_error)?;
    let model = endpoint.model();
    writeln!(
        output,
        "    model: {} - {}",
        endpoint_role(model.role),
        escape_terminal_text(&model.display_name),
    )
    .map_err(map_io_error)?;
    write_text_items(
        output,
        "      category",
        model.categories.iter().map(|value| value.as_str()),
    )?;
    write!(output, "      binding: ").map_err(map_io_error)?;
    write_endpoint_binding(output, &model.binding)?;
    writeln!(output).map_err(map_io_error)?;
    if let Some(taint) = &model.taint {
        write_endpoint_taint(output, taint)?;
    }
    for superseded in &model.supersedes {
        write!(output, "      supersedes: ").map_err(map_io_error)?;
        write_endpoint_identity(output, superseded)?;
        writeln!(output).map_err(map_io_error)?;
    }
    for origin in endpoint.origins() {
        write_endpoint_origin(output, origin)?;
    }
    Ok(())
}

fn write_endpoint_definition_schema<W: Write>(
    output: &mut BoundedWriter<W>,
    schema: &EndpointDefinitionSchemaResolution,
) -> Result<(), PolicyRenderError> {
    match schema {
        EndpointDefinitionSchemaResolution::PolicyDocument { resolution } => {
            write!(output, "policy document ").map_err(map_io_error)?;
            write_schema_resolution_value(output, *resolution)
        }
        EndpointDefinitionSchemaResolution::CatalogDocument { schema_version } => {
            write!(output, "catalog document {schema_version}").map_err(map_io_error)
        }
    }
}

fn write_endpoint_binding<W: Write>(
    output: &mut BoundedWriter<W>,
    binding: &PolicyEndpointBinding,
) -> Result<(), PolicyRenderError> {
    match binding {
        PolicyEndpointBinding::MatchedValue => write!(output, "matched value"),
        PolicyEndpointBinding::Receiver => write!(output, "receiver"),
        PolicyEndpointBinding::ReturnValue => write!(output, "return value"),
        PolicyEndpointBinding::ArgumentIndex { index } => write!(output, "argument {index}"),
        PolicyEndpointBinding::ArgumentName { name } => {
            write!(output, "argument {}", escape_terminal_text(name))
        }
    }
    .map_err(map_io_error)
}

fn write_endpoint_taint<W: Write>(
    output: &mut BoundedWriter<W>,
    taint: &EndpointTaintSemantics,
) -> Result<(), PolicyRenderError> {
    match taint {
        EndpointTaintSemantics::Source { labels, evidence } => {
            writeln!(output, "      taint: source").map_err(map_io_error)?;
            write_text_items(
                output,
                "        label",
                labels.iter().map(|value| value.as_str()),
            )?;
            if let Some(evidence) = evidence {
                write_taint_source_evidence(output, "        evidence", evidence)?;
            }
        }
        EndpointTaintSemantics::Sink {
            accepts,
            tags,
            impacts,
        } => {
            writeln!(output, "      taint: sink").map_err(map_io_error)?;
            write_text_items(
                output,
                "        accepts",
                accepts.iter().map(|value| value.as_str()),
            )?;
            write_text_items(
                output,
                "        tag",
                tags.iter().map(|value| value.as_str()),
            )?;
            write_text_items(
                output,
                "        impact",
                impacts.iter().map(|value| value.as_str()),
            )?;
        }
    }
    Ok(())
}

fn write_taint_source_evidence<W: Write>(
    output: &mut BoundedWriter<W>,
    label: &str,
    evidence: &TaintSourceEvidence,
) -> Result<(), PolicyRenderError> {
    write!(output, "{label}:").map_err(map_io_error)?;
    if let Some(boundary) = evidence.trust_boundary {
        write!(output, " trust boundary {}", taint_trust_boundary(boundary))
            .map_err(map_io_error)?;
    }
    if let Some(entry) = evidence.system_entry {
        write!(output, " system entry {}", taint_system_entry(entry)).map_err(map_io_error)?;
    }
    writeln!(output).map_err(map_io_error)
}

fn write_endpoint_origin<W: Write>(
    output: &mut BoundedWriter<W>,
    origin: &EndpointOrigin,
) -> Result<(), PolicyRenderError> {
    write!(output, "      origin: ").map_err(map_io_error)?;
    match origin {
        EndpointOrigin::PolicyLocal { path } => write!(
            output,
            "policy local {}",
            escape_terminal_text(path.as_str()),
        )
        .map_err(map_io_error)?,
        EndpointOrigin::Catalog { catalog } => write!(
            output,
            "catalog {}@{} ({})",
            escape_terminal_text(catalog.name.as_str()),
            catalog.version,
            catalog.semantic_hash,
        )
        .map_err(map_io_error)?,
        EndpointOrigin::ExactMatch { path, source } => write!(
            output,
            "exact match {} from {}",
            escape_terminal_text(path.as_str()),
            escape_terminal_text(source.as_str()),
        )
        .map_err(map_io_error)?,
        EndpointOrigin::MatchDirectory { path, source } => write!(
            output,
            "match directory {} from {}",
            escape_terminal_text(path.as_str()),
            escape_terminal_text(source.as_str()),
        )
        .map_err(map_io_error)?,
    }
    writeln!(output).map_err(map_io_error)
}

fn write_match_directory_manifest<W: Write>(
    output: &mut BoundedWriter<W>,
    manifest: &ResolvedMatchDirectoryManifest,
) -> Result<(), PolicyRenderError> {
    writeln!(
        output,
        "  match directory {}: {} ({}, role {}, hash {})",
        escape_terminal_text(manifest.path().as_str()),
        escape_terminal_text(manifest.directory().as_str()),
        directory_scope(manifest.scope()),
        manifest.role().map_or("any", endpoint_role),
        manifest.semantic_hash(),
    )
    .map_err(map_io_error)?;
    write_category_predicate(output, "    categories", manifest.categories())?;
    for selected in manifest.selected() {
        write_manifest_entry(output, selected)?;
    }
    Ok(())
}

fn write_manifest_entry<W: Write>(
    output: &mut BoundedWriter<W>,
    entry: &ResolvedEndpointManifestEntry,
) -> Result<(), PolicyRenderError> {
    write!(output, "    selected endpoint: ").map_err(map_io_error)?;
    write_endpoint_identity(output, &entry.identity)?;
    writeln!(output).map_err(map_io_error)?;
    write!(output, "      definition schema: ").map_err(map_io_error)?;
    write_endpoint_definition_schema(output, &entry.definition_schema)?;
    writeln!(output).map_err(map_io_error)?;
    write!(output, "      selector schema: ").map_err(map_io_error)?;
    write_schema_resolution_value(output, entry.selector_schema)?;
    writeln!(output).map_err(map_io_error)?;
    writeln!(output, "      semantic hash: {}", entry.semantic_hash).map_err(map_io_error)?;
    writeln!(
        output,
        "      analysis projection hash: {}",
        entry.analysis_projection_hash,
    )
    .map_err(map_io_error)
}

fn write_precedence_edge<W: Write>(
    output: &mut BoundedWriter<W>,
    edge: &ResolvedPrecedenceEdge,
) -> Result<(), PolicyRenderError> {
    write!(output, "  precedence: ").map_err(map_io_error)?;
    match edge {
        ResolvedPrecedenceEdge::Endpoint {
            dominant,
            dominated,
        } => {
            write!(output, "endpoint ").map_err(map_io_error)?;
            write_endpoint_identity(output, dominant)?;
            write!(output, " > ").map_err(map_io_error)?;
            write_endpoint_identity(output, dominated)?;
        }
        ResolvedPrecedenceEdge::FindingCombination {
            dominant,
            dominated,
        } => write!(
            output,
            "finding combination {} > {}",
            escape_terminal_text(dominant.as_str()),
            escape_terminal_text(dominated.as_str()),
        )
        .map_err(map_io_error)?,
        ResolvedPrecedenceEdge::TypestateEvent {
            dominant,
            dominated,
        } => write!(
            output,
            "typestate event {} > {}",
            escape_terminal_text(dominant.as_str()),
            escape_terminal_text(dominated.as_str()),
        )
        .map_err(map_io_error)?,
        ResolvedPrecedenceEdge::TypestateExpectation {
            dominant,
            dominated,
        } => write!(
            output,
            "typestate expectation {} > {}",
            escape_terminal_text(dominant.as_str()),
            escape_terminal_text(dominated.as_str()),
        )
        .map_err(map_io_error)?,
    }
    writeln!(output).map_err(map_io_error)
}

fn write_category_predicate<W: Write>(
    output: &mut BoundedWriter<W>,
    label: &str,
    predicate: &CategoryPredicate,
) -> Result<(), PolicyRenderError> {
    let (quantifier, categories) = match predicate {
        CategoryPredicate::Any { categories } => ("any", categories),
        CategoryPredicate::All { categories } => ("all", categories),
    };
    writeln!(output, "{label}: {quantifier}").map_err(map_io_error)?;
    write_text_items(
        output,
        "      category",
        categories.iter().map(|value| value.as_str()),
    )
}

fn write_schema_resolution<W: Write>(
    output: &mut BoundedWriter<W>,
    label: &str,
    resolution: SchemaVersionResolution,
) -> Result<(), PolicyRenderError> {
    write!(output, "{label}: ").map_err(map_io_error)?;
    write_schema_resolution_value(output, resolution)?;
    writeln!(output).map_err(map_io_error)
}

fn write_schema_resolution_value<W: Write>(
    output: &mut BoundedWriter<W>,
    resolution: SchemaVersionResolution,
) -> Result<(), PolicyRenderError> {
    write!(
        output,
        "{} ({})",
        resolution.version,
        schema_version_origin(resolution.origin),
    )
    .map_err(map_io_error)
}

fn named_cvss_component(
    components: &[CvssComponentResult],
    nomenclature: CvssNomenclature,
) -> Result<&CvssComponentResult, PolicyRenderError> {
    components
        .iter()
        .find(|component| component.nomenclature() == nomenclature)
        .ok_or(PolicyRenderError::InvalidCanonicalReport {
            detail: "a scored CVSS assessment is missing its named component",
        })
}

fn write_cvss_variant_detail<W: Write>(
    output: &mut BoundedWriter<W>,
    variant: &CvssAssessmentVariant,
) -> Result<(), PolicyRenderError> {
    writeln!(
        output,
        "    vulnerability identity: {}",
        variant.vulnerability_identity(),
    )
    .map_err(map_io_error)?;
    write_text_items(
        output,
        "    source scenario",
        variant
            .source_scenarios()
            .iter()
            .map(|value| value.as_str()),
    )?;
    if variant.source_scenarios_truncated() {
        writeln!(
            output,
            "    source scenarios truncated: at least {} omitted",
            variant.omitted_source_scenarios_lower_bound(),
        )
        .map_err(map_io_error)?;
    }
    writeln!(
        output,
        "    source scenario set: {}",
        variant.source_scenario_set_hash(),
    )
    .map_err(map_io_error)?;
    write_text_items(
        output,
        "    witness reference",
        variant.witness_refs().iter().map(|value| value.as_str()),
    )?;
    if variant.witness_refs_truncated() {
        writeln!(output, "    witness references: truncated").map_err(map_io_error)?;
    }

    match variant.assessment() {
        CvssAssessment::Scored {
            version,
            nomenclature,
            vector,
            components,
            metrics,
            provenance,
        } => {
            writeln!(
                output,
                "    scored assessment: CVSS {} {}",
                cvss_version(*version),
                cvss_nomenclature(*nomenclature),
            )
            .map_err(map_io_error)?;
            writeln!(output, "      vector: {}", escape_terminal_text(vector),)
                .map_err(map_io_error)?;
            for component in components {
                writeln!(
                    output,
                    "      component {}: {:.1} {} {}",
                    cvss_nomenclature(component.nomenclature()),
                    component.score(),
                    cvss_severity(component.severity()),
                    escape_terminal_text(component.vector()),
                )
                .map_err(map_io_error)?;
            }
            for metric in metrics {
                write_cvss_metric_evidence(output, "      metric", metric)?;
            }
            write_cvss_provenance(output, provenance)?;
        }
        CvssAssessment::Unscored {
            version,
            established,
            missing_base_metrics,
            reasons,
            provenance,
        } => {
            writeln!(
                output,
                "    unscored assessment: CVSS {}",
                cvss_version(*version)
            )
            .map_err(map_io_error)?;
            for metric in established {
                write_cvss_metric_evidence(output, "      established metric", metric)?;
            }
            for metric in missing_base_metrics {
                writeln!(
                    output,
                    "      missing base metric: {}",
                    metric.first_label()
                )
                .map_err(map_io_error)?;
            }
            for reason in reasons {
                write_cvss_unscored_reason(output, reason)?;
            }
            write_cvss_provenance(output, provenance)?;
        }
    }
    Ok(())
}

fn write_cvss_metric_evidence<W: Write>(
    output: &mut BoundedWriter<W>,
    label: &str,
    evidence: &CvssMetricEvidence,
) -> Result<(), PolicyRenderError> {
    writeln!(
        output,
        "{label}: {}={} ({}, {}; hash {})",
        evidence.metric().first_label(),
        evidence.value().first_label(),
        cvss_evidence_basis(evidence.basis()),
        cvss_evidence_scope(evidence.system_scope()),
        evidence.content_hash(),
    )
    .map_err(map_io_error)?;
    writeln!(
        output,
        "        rationale: {}",
        escape_terminal_text(evidence.rationale()),
    )
    .map_err(map_io_error)?;
    writeln!(
        output,
        "        assessor or tool: {}",
        escape_terminal_text(evidence.assessor_or_tool()),
    )
    .map_err(map_io_error)?;
    if let Some(assessed_at) = evidence.assessed_at() {
        writeln!(
            output,
            "        assessed at: {}",
            escape_terminal_text(assessed_at),
        )
        .map_err(map_io_error)?;
    }
    write_text_items(
        output,
        "        evidence",
        evidence.evidence_refs().iter().map(|value| value.as_str()),
    )?;
    write_text_items(
        output,
        "        assumption",
        evidence.assumptions().iter().map(String::as_str),
    )
}

fn write_cvss_unscored_reason<W: Write>(
    output: &mut BoundedWriter<W>,
    reason: &CvssUnscoredReason,
) -> Result<(), PolicyRenderError> {
    match reason {
        CvssUnscoredReason::MissingBaseEvidence => {
            writeln!(output, "      unscored reason: missing base evidence")
                .map_err(map_io_error)?;
        }
        CvssUnscoredReason::ConflictingMetricEvidence {
            metric,
            evidence_set_hash,
            evidence_refs,
            evidence_refs_truncated,
            omitted_evidence_refs_lower_bound,
        } => {
            writeln!(
                output,
                "      unscored reason: conflicting {} evidence (set {})",
                metric.first_label(),
                evidence_set_hash,
            )
            .map_err(map_io_error)?;
            write_text_items(
                output,
                "        conflicting evidence",
                evidence_refs.iter().map(|value| value.as_str()),
            )?;
            if *evidence_refs_truncated {
                writeln!(
                    output,
                    "        conflicting evidence truncated: at least {} omitted",
                    omitted_evidence_refs_lower_bound,
                )
                .map_err(map_io_error)?;
            }
        }
        CvssUnscoredReason::IncoherentScenario {
            scenario_set_hash,
            scenario_ids,
            scenario_ids_truncated,
            omitted_scenario_ids_lower_bound,
            rationale,
        } => {
            writeln!(
                output,
                "      unscored reason: incoherent scenarios (set {}) - {}",
                scenario_set_hash,
                escape_terminal_text(rationale),
            )
            .map_err(map_io_error)?;
            write_text_items(
                output,
                "        incoherent scenario",
                scenario_ids.iter().map(|value| value.as_str()),
            )?;
            if *scenario_ids_truncated {
                writeln!(
                    output,
                    "        incoherent scenarios truncated: at least {} omitted",
                    omitted_scenario_ids_lower_bound,
                )
                .map_err(map_io_error)?;
            }
        }
        CvssUnscoredReason::RunIncomplete { reason } => {
            writeln!(
                output,
                "      unscored reason: run incomplete ({})",
                incomplete_reason(*reason),
            )
            .map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_cvss_provenance<W: Write>(
    output: &mut BoundedWriter<W>,
    provenance: &CvssAssessmentProvenance,
) -> Result<(), PolicyRenderError> {
    writeln!(
        output,
        "      reducer: {}",
        escape_terminal_text(provenance.reducer()),
    )
    .map_err(map_io_error)?;
    write_text_items(
        output,
        "      provenance evidence",
        provenance
            .evidence_refs()
            .iter()
            .map(|value| value.as_str()),
    )?;
    for scope in provenance.overlay_scopes() {
        write!(output, "      overlay scope: ").map_err(map_io_error)?;
        write_overlay_scope(output, scope)?;
        writeln!(output).map_err(map_io_error)?;
    }
    for hash in provenance.content_hashes() {
        writeln!(output, "      evidence content hash: {hash}").map_err(map_io_error)?;
    }
    Ok(())
}

fn write_overlay_scope<W: Write>(
    output: &mut BoundedWriter<W>,
    scope: &PolicyOverlayScope,
) -> Result<(), PolicyRenderError> {
    match scope {
        PolicyOverlayScope::AllFindings => write!(output, "all findings"),
        PolicyOverlayScope::Policy { policy_id } => write!(
            output,
            "policy {}",
            escape_terminal_text(policy_id.as_str()),
        ),
        PolicyOverlayScope::Finding { finding_id } => write!(output, "finding {finding_id}"),
        PolicyOverlayScope::SourceScenario { scenario_id } => write!(
            output,
            "source scenario {}",
            escape_terminal_text(scenario_id.as_str()),
        ),
        PolicyOverlayScope::FindingScenario { finding, scenario } => write!(
            output,
            "finding {finding}, source scenario {}",
            escape_terminal_text(scenario.as_str()),
        ),
    }
    .map_err(map_io_error)
}

fn write_evidence_summary<W: Write>(
    output: &mut BoundedWriter<W>,
    finding: &PolicyFinding,
) -> Result<(), PolicyRenderError> {
    match finding.evidence() {
        PolicyFindingEvidence::Match { evidence } => {
            write!(
                output,
                "  evidence: {}",
                match_result_domain(evidence.result_domain())
            )
            .map_err(map_io_error)?;
            write_query_result_detail(output, evidence.terminal())?;
            if evidence.provenance_truncated() {
                write!(output, " (provenance truncated)").map_err(map_io_error)?;
            }
            writeln!(output).map_err(map_io_error)?;
        }
        PolicyFindingEvidence::Taint { evidence } => {
            write!(
                output,
                "  evidence: taint {} [source ",
                escape_terminal_text(evidence.source_display_name()),
            )
            .map_err(map_io_error)?;
            write_endpoint_identity(output, evidence.source_endpoint())?;
            write!(
                output,
                "] -> {} [sink ",
                escape_terminal_text(evidence.sink_display_name()),
            )
            .map_err(map_io_error)?;
            write_endpoint_identity(output, evidence.sink_endpoint())?;
            write!(output, "]; combination ").map_err(map_io_error)?;
            if let Some(combination) = evidence.selected_combination() {
                write!(output, "{}", escape_terminal_text(combination.as_str()),)
                    .map_err(map_io_error)?;
            } else {
                write!(output, "generated-default").map_err(map_io_error)?;
            }
            write!(
                output,
                "; {} source scenario{}{}",
                evidence.source_scenarios().len(),
                plural_suffix(evidence.source_scenarios().len()),
                if evidence.source_scenarios_truncated() {
                    ", truncated"
                } else {
                    ""
                },
            )
            .map_err(map_io_error)?;
            writeln!(output).map_err(map_io_error)?;
        }
        PolicyFindingEvidence::Typestate { evidence } => {
            write!(
                output,
                "  evidence: typestate subject {}; source ",
                escape_terminal_text(evidence.subject().as_str()),
            )
            .map_err(map_io_error)?;
            write_endpoint_identity(output, evidence.source_endpoint())?;
            writeln!(
                output,
                "; violation {}; {} scenario{}{}",
                match evidence.violation() {
                    super::super::TypestateViolationEvidence::ErrorTransition { .. } => {
                        "error-transition"
                    }
                    super::super::TypestateViolationEvidence::TerminalExpectation { .. } => {
                        "terminal-expectation"
                    }
                },
                evidence.scenario_ids().len(),
                plural_suffix(evidence.scenario_ids().len()),
                if evidence.scenarios_truncated() {
                    ", truncated"
                } else {
                    ""
                },
            )
            .map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_evidence_detail<W: Write>(
    output: &mut BoundedWriter<W>,
    evidence: &PolicyFindingEvidence,
) -> Result<(), PolicyRenderError> {
    match evidence {
        PolicyFindingEvidence::Match { evidence } => {
            write_match_anchor(output, evidence.anchor())?;
            write_query_result_line(output, "  match terminal", evidence.terminal())?;
            for provenance in evidence.provenance() {
                write_query_provenance(output, provenance)?;
            }
            if evidence.provenance_truncated() {
                writeln!(output, "  query provenance: truncated").map_err(map_io_error)?;
            }
        }
        PolicyFindingEvidence::Taint { evidence } => {
            if let Some(anchor) = evidence.anchor().strong_fields() {
                write!(output, "  taint anchor: strong; sink identity ").map_err(map_io_error)?;
                write_optional_stable_identity(output, Some(anchor.sink_identity()))?;
                writeln!(output).map_err(map_io_error)?;
                writeln!(
                    output,
                    "    source endpoint projection: {}",
                    anchor.source_endpoint_analysis_projection_hash(),
                )
                .map_err(map_io_error)?;
                writeln!(
                    output,
                    "    sink endpoint projection: {}",
                    anchor.sink_endpoint_analysis_projection_hash(),
                )
                .map_err(map_io_error)?;
                writeln!(
                    output,
                    "    source scenario set: {}",
                    anchor.source_scenario_set_hash(),
                )
                .map_err(map_io_error)?;
            } else if let Some(anchor) = evidence.anchor().weak_fields() {
                writeln!(
                    output,
                    "  taint anchor: weak; typed key {}",
                    escape_terminal_text(anchor.typed_key().as_str()),
                )
                .map_err(map_io_error)?;
            }
            writeln!(
                output,
                "  analysis finding: {}",
                escape_terminal_text(evidence.analysis_finding_id().as_str()),
            )
            .map_err(map_io_error)?;
            writeln!(
                output,
                "  sink event: {}",
                escape_terminal_text(evidence.sink().as_str()),
            )
            .map_err(map_io_error)?;
            write_text_items(
                output,
                "  source category",
                evidence
                    .source_categories()
                    .iter()
                    .map(|value| value.as_str()),
            )?;
            write_text_items(
                output,
                "  sink category",
                evidence
                    .sink_categories()
                    .iter()
                    .map(|value| value.as_str()),
            )?;
            write_text_items(
                output,
                "  sink tag",
                evidence.sink_tags().iter().map(|value| value.as_str()),
            )?;
            write_text_items(
                output,
                "  sink impact",
                evidence.sink_impacts().iter().map(|value| value.as_str()),
            )?;
            write_text_items(
                output,
                "  reached source label",
                evidence
                    .reached_source_labels()
                    .iter()
                    .map(|value| value.as_str()),
            )?;
            for origin in evidence.origins() {
                write!(
                    output,
                    "  taint origin {}: {} from ",
                    escape_terminal_text(origin.scenario_id().as_str()),
                    escape_terminal_text(origin.source_label().as_str()),
                )
                .map_err(map_io_error)?;
                write_endpoint_identity(output, origin.source_endpoint())?;
                write!(output, " at ").map_err(map_io_error)?;
                write_location(output, origin.primary()).map_err(map_io_error)?;
                write_evidence_refs_suffix(output, origin.evidence_refs())?;
                writeln!(output).map_err(map_io_error)?;
                if let Some(source_evidence) = origin.source_evidence() {
                    write_taint_source_evidence(output, "    source evidence", source_evidence)?;
                }
            }
            if evidence.origins_truncated() {
                writeln!(output, "  taint origins: truncated").map_err(map_io_error)?;
            }
            write_text_items(
                output,
                "  source scenario",
                evidence
                    .source_scenarios()
                    .iter()
                    .map(|value| value.as_str()),
            )?;
            if evidence.source_scenarios_truncated() {
                writeln!(
                    output,
                    "  source scenarios truncated: at least {} omitted",
                    evidence.omitted_source_scenarios_lower_bound(),
                )
                .map_err(map_io_error)?;
            }
            writeln!(
                output,
                "  source scenario set: {}",
                evidence.source_scenario_set_hash(),
            )
            .map_err(map_io_error)?;
            write_text_items(
                output,
                "  taint witness reference",
                evidence.witness_refs().iter().map(|value| value.as_str()),
            )?;
            if evidence.witness_refs_truncated() {
                writeln!(output, "  taint witness references: truncated").map_err(map_io_error)?;
            }
            writeln!(
                output,
                "  taint projection: {}",
                evidence.projection_facts_hash(),
            )
            .map_err(map_io_error)?;
        }
        PolicyFindingEvidence::Typestate { evidence } => {
            if let Some(anchor) = evidence.anchor().strong_fields() {
                writeln!(output, "  typestate anchor: strong").map_err(map_io_error)?;
                writeln!(output, "    protocol hash: {}", anchor.protocol_hash())
                    .map_err(map_io_error)?;
                writeln!(
                    output,
                    "    binding plan hash: {}",
                    anchor.binding_plan_hash()
                )
                .map_err(map_io_error)?;
                write!(output, "    subject identity: ").map_err(map_io_error)?;
                write_optional_stable_identity(output, Some(anchor.subject_identity()))?;
                writeln!(output).map_err(map_io_error)?;
                write!(output, "    violation site identity: ").map_err(map_io_error)?;
                write_optional_stable_identity(output, Some(anchor.violation_site_identity()))?;
                writeln!(output).map_err(map_io_error)?;
                writeln!(output, "    scenario set: {}", anchor.scenario_set_hash())
                    .map_err(map_io_error)?;
                writeln!(output, "    violation hash: {}", anchor.violation_hash())
                    .map_err(map_io_error)?;
            } else if let Some(anchor) = evidence.anchor().weak_fields() {
                writeln!(
                    output,
                    "  typestate anchor: weak; typed key {}",
                    escape_terminal_text(anchor.typed_key().as_str()),
                )
                .map_err(map_io_error)?;
            }
            writeln!(
                output,
                "  analysis finding: {}",
                escape_terminal_text(evidence.analysis_finding_id().as_str()),
            )
            .map_err(map_io_error)?;
            writeln!(output, "  typestate protocol: {}", evidence.protocol_hash())
                .map_err(map_io_error)?;
            writeln!(
                output,
                "  typestate binding plan: {}",
                evidence.binding_plan_hash(),
            )
            .map_err(map_io_error)?;
            if let Some(site) = evidence.violation_site() {
                write!(output, "  violation site: ").map_err(map_io_error)?;
                write_optional_stable_identity(output, Some(site))?;
                writeln!(output).map_err(map_io_error)?;
            } else {
                writeln!(output, "  violation site: unavailable").map_err(map_io_error)?;
            }
            write_typestate_violation(output, evidence.violation())?;
            write_text_items(
                output,
                "  typestate scenario",
                evidence.scenario_ids().iter().map(|value| value.as_str()),
            )?;
            if evidence.scenarios_truncated() {
                writeln!(
                    output,
                    "  typestate scenarios truncated: at least {} omitted",
                    evidence.omitted_scenarios_lower_bound(),
                )
                .map_err(map_io_error)?;
            }
            writeln!(
                output,
                "  typestate scenario set: {}",
                evidence.scenario_set_hash()
            )
            .map_err(map_io_error)?;
            write_text_items(
                output,
                "  typestate witness reference",
                evidence.witness_refs().iter().map(|value| value.as_str()),
            )?;
            if evidence.witness_refs_truncated() {
                writeln!(output, "  typestate witness references: truncated")
                    .map_err(map_io_error)?;
            }
            writeln!(
                output,
                "  typestate projection: {}",
                evidence.projection_facts_hash(),
            )
            .map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_match_anchor<W: Write>(
    output: &mut BoundedWriter<W>,
    anchor: &MatchFindingAnchor,
) -> Result<(), PolicyRenderError> {
    match anchor {
        MatchFindingAnchor::Strong(anchor) => {
            writeln!(
                output,
                "  match anchor: strong {} {}",
                match_result_domain(anchor.result_domain()),
                escape_terminal_text(anchor.path().as_str()),
            )
            .map_err(map_io_error)?;
            write!(output, "    semantic owner: ").map_err(map_io_error)?;
            write_optional_stable_identity(output, anchor.semantic_owner())?;
            writeln!(output).map_err(map_io_error)?;
            if let Some(hash) = anchor.selected_source_sha256() {
                writeln!(output, "    selected source: {hash}").map_err(map_io_error)?;
            } else {
                writeln!(output, "    selected source: unavailable").map_err(map_io_error)?;
            }
            writeln!(
                output,
                "    occurrence ordinal: {}",
                anchor.occurrence_ordinal(),
            )
            .map_err(map_io_error)?;
        }
        MatchFindingAnchor::Weak(anchor) => {
            writeln!(
                output,
                "  match anchor: weak {} {}",
                match_result_domain(anchor.result_domain()),
                escape_terminal_text(anchor.path().as_str()),
            )
            .map_err(map_io_error)?;
            writeln!(
                output,
                "    typed key: {}",
                escape_terminal_text(anchor.typed_key().as_str()),
            )
            .map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_query_provenance<W: Write>(
    output: &mut BoundedWriter<W>,
    provenance: &PolicyQueryProvenance,
) -> Result<(), PolicyRenderError> {
    write!(output, "  query provenance branch:").map_err(map_io_error)?;
    if provenance.branch().is_empty() {
        write!(output, " root").map_err(map_io_error)?;
    } else {
        for index in provenance.branch() {
            write!(output, " {index}").map_err(map_io_error)?;
        }
    }
    writeln!(output).map_err(map_io_error)?;
    write_query_result_line(output, "    seed", provenance.seed())?;
    for step in provenance.steps() {
        write_query_result_line(output, "    result", step.result())?;
        writeln!(
            output,
            "      operation: {}",
            escape_terminal_text(step.operation()),
        )
        .map_err(map_io_error)?;
        if let Some(via) = step.via() {
            write_query_result_line(output, "      via", via)?;
        }
    }
    Ok(())
}

fn write_query_result_line<W: Write>(
    output: &mut BoundedWriter<W>,
    label: &str,
    result: &PolicyQueryResultRef,
) -> Result<(), PolicyRenderError> {
    write!(output, "{label}: {}", query_result_kind(result)).map_err(map_io_error)?;
    write_query_result_detail(output, result)?;
    if let PolicyQueryResultRef::StructuralMatch { identity, .. } = result {
        write!(output, "; identity ").map_err(map_io_error)?;
        write_optional_stable_identity(output, identity.as_ref())?;
    }
    if !matches!(result, PolicyQueryResultRef::File { .. })
        && let Some(location) = result.location()
    {
        write!(output, " at ").map_err(map_io_error)?;
        write_location(output, location).map_err(map_io_error)?;
    }
    writeln!(output).map_err(map_io_error)
}

fn write_typestate_violation<W: Write>(
    output: &mut BoundedWriter<W>,
    violation: &TypestateViolationEvidence,
) -> Result<(), PolicyRenderError> {
    match violation {
        TypestateViolationEvidence::ErrorTransition {
            event_id,
            endpoint,
            from,
            to,
        } => {
            write!(
                output,
                "  error transition {}: {} -> {}",
                escape_terminal_text(event_id.as_str()),
                escape_terminal_text(from.as_str()),
                escape_terminal_text(to.as_str()),
            )
            .map_err(map_io_error)?;
            if let Some(endpoint) = endpoint {
                write!(output, "; endpoint ").map_err(map_io_error)?;
                write_endpoint_identity(output, endpoint)?;
            }
            writeln!(output).map_err(map_io_error)?;
        }
        TypestateViolationEvidence::TerminalExpectation {
            expectation_id,
            terminal,
            observed_state,
            expected_states,
        } => {
            write!(
                output,
                "  terminal expectation {}: observed {} at ",
                escape_terminal_text(expectation_id.as_str()),
                escape_terminal_text(observed_state.as_str()),
            )
            .map_err(map_io_error)?;
            write_typestate_terminal(output, terminal)?;
            writeln!(output).map_err(map_io_error)?;
            write_text_items(
                output,
                "    expected state",
                expected_states.iter().map(|value| value.as_str()),
            )?;
        }
    }
    Ok(())
}

fn write_typestate_terminal<W: Write>(
    output: &mut BoundedWriter<W>,
    terminal: &ResolvedTypestateTerminal,
) -> Result<(), PolicyRenderError> {
    match terminal {
        ResolvedTypestateTerminal::Endpoint { endpoint, phase } => {
            write!(output, "endpoint ").map_err(map_io_error)?;
            write_endpoint_identity(output, endpoint)?;
            write!(output, " ({})", endpoint_phase(*phase)).map_err(map_io_error)
        }
        ResolvedTypestateTerminal::SemanticEvent { event } => {
            write!(output, "semantic event {}", semantic_event(*event)).map_err(map_io_error)
        }
    }
}

fn write_certainty_detail<W: Write>(
    output: &mut BoundedWriter<W>,
    certainty: &FindingCertainty,
) -> Result<(), PolicyRenderError> {
    for reason in certainty.reasons() {
        write!(output, "  certainty reason: ").map_err(map_io_error)?;
        match reason {
            CertaintyReason::AnalyzerAmbiguity { code } => {
                write!(output, "analyzer ambiguity {}", escape_terminal_text(code),)
                    .map_err(map_io_error)?
            }
            _ => write!(output, "{}", certainty_reason(reason)).map_err(map_io_error)?,
        }
        writeln!(output).map_err(map_io_error)?;
    }
    Ok(())
}

fn write_proof_detail<W: Write>(
    output: &mut BoundedWriter<W>,
    proof: &ProofMetadata,
) -> Result<(), PolicyRenderError> {
    for reason in proof.reasons() {
        write!(output, "  proof reason: ").map_err(map_io_error)?;
        match reason {
            ProofReason::AnalyzerEvidence { code } => {
                write!(output, "analyzer evidence {}", escape_terminal_text(code))
                    .map_err(map_io_error)?;
            }
            _ => write!(output, "{}", proof_reason(reason)).map_err(map_io_error)?,
        }
        writeln!(output).map_err(map_io_error)?;
    }
    write_text_items(
        output,
        "  proof evidence",
        proof.evidence_refs().iter().map(|value| value.as_str()),
    )
}

fn write_organizational_risk<W: Write>(
    output: &mut BoundedWriter<W>,
    risk: &OrganizationalRiskAssessment,
) -> Result<(), PolicyRenderError> {
    writeln!(
        output,
        "  organizational risk: {} {} - {}",
        escape_terminal_text(risk.scheme()),
        escape_terminal_text(risk.rating()),
        escape_terminal_text(risk.rationale()),
    )
    .map_err(map_io_error)?;
    if let Some(assessor) = risk.assessor() {
        writeln!(output, "    assessor: {}", escape_terminal_text(assessor),)
            .map_err(map_io_error)?;
    }
    write_text_items(
        output,
        "    risk evidence",
        risk.evidence_refs().iter().map(|value| value.as_str()),
    )?;
    writeln!(output, "    assessment hash: {}", risk.content_hash()).map_err(map_io_error)
}

fn write_evidence_refs_suffix<W: Write>(
    output: &mut BoundedWriter<W>,
    evidence_refs: &[EvidenceRef],
) -> Result<(), PolicyRenderError> {
    if evidence_refs.is_empty() {
        return Ok(());
    }
    write!(output, " [evidence").map_err(map_io_error)?;
    for evidence in evidence_refs {
        write!(output, " {}", escape_terminal_text(evidence.as_str())).map_err(map_io_error)?;
    }
    write!(output, "]").map_err(map_io_error)
}

fn write_text_items<'a, W, I>(
    output: &mut BoundedWriter<W>,
    label: &str,
    values: I,
) -> Result<(), PolicyRenderError>
where
    W: Write,
    I: IntoIterator<Item = &'a str>,
{
    for value in values {
        writeln!(output, "{label}: {}", escape_terminal_text(value)).map_err(map_io_error)?;
    }
    Ok(())
}

fn write_query_result_detail<W: Write>(
    output: &mut BoundedWriter<W>,
    result: &PolicyQueryResultRef,
) -> Result<(), PolicyRenderError> {
    match result {
        PolicyQueryResultRef::StructuralMatch { kind, .. } => {
            write!(output, " {}", escape_terminal_text(kind)).map_err(map_io_error)?;
        }
        PolicyQueryResultRef::Declaration {
            kind,
            fq_name,
            identity,
            ..
        } => {
            write!(
                output,
                " {} {}; identity ",
                escape_terminal_text(kind),
                escape_terminal_text(fq_name),
            )
            .map_err(map_io_error)?;
            write_optional_stable_identity(output, identity.as_ref())?;
        }
        PolicyQueryResultRef::File { path } => {
            write!(output, " {}", escape_terminal_text(path.as_str())).map_err(map_io_error)?;
        }
        PolicyQueryResultRef::ReferenceSite {
            target_fq_name,
            target_identity,
            usage_kind,
            proof,
            ..
        } => {
            write!(
                output,
                " target {}; target identity ",
                escape_terminal_text(target_fq_name),
            )
            .map_err(map_io_error)?;
            write_optional_stable_identity(output, target_identity.as_ref())?;
            write!(output, "; usage ").map_err(map_io_error)?;
            if let Some(kind) = usage_kind {
                write!(output, "{}", escape_terminal_text(kind)).map_err(map_io_error)?;
            } else {
                write!(output, "unspecified").map_err(map_io_error)?;
            }
            write!(output, "; proof {}", query_proof(*proof)).map_err(map_io_error)?;
        }
        PolicyQueryResultRef::CallSite {
            caller_fq_name,
            caller_identity,
            callee_fq_name,
            callee_identity,
            proof,
            ..
        } => {
            write!(
                output,
                " call {} [identity ",
                escape_terminal_text(caller_fq_name),
            )
            .map_err(map_io_error)?;
            write_optional_stable_identity(output, caller_identity.as_ref())?;
            write!(
                output,
                "] -> {} [identity ",
                escape_terminal_text(callee_fq_name),
            )
            .map_err(map_io_error)?;
            write_optional_stable_identity(output, callee_identity.as_ref())?;
            write!(output, "]; proof {}", query_proof(*proof)).map_err(map_io_error)?;
        }
        PolicyQueryResultRef::ExpressionSite {
            input_kind,
            parameter_index,
            parameter_name,
            ..
        } => {
            write!(output, " {}", escape_terminal_text(input_kind)).map_err(map_io_error)?;
            if let Some(index) = parameter_index {
                write!(output, "; parameter index {index}").map_err(map_io_error)?;
            }
            if let Some(name) = parameter_name {
                write!(output, "; parameter name {}", escape_terminal_text(name))
                    .map_err(map_io_error)?;
            }
        }
        PolicyQueryResultRef::ReceiverAnalysis {
            analysis_kind,
            outcome,
            capture,
            ..
        } => {
            write!(
                output,
                " {}; outcome {}",
                escape_terminal_text(analysis_kind),
                escape_terminal_text(outcome),
            )
            .map_err(map_io_error)?;
            if let Some(capture) = capture {
                write!(output, "; capture {}", escape_terminal_text(capture))
                    .map_err(map_io_error)?;
            }
        }
        PolicyQueryResultRef::Unsupported {
            query_result_kind, ..
        } => {
            write!(output, " {}", escape_terminal_text(query_result_kind)).map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_endpoint_identity<W: Write>(
    output: &mut BoundedWriter<W>,
    identity: &ResolvedEndpointIdentity,
) -> Result<(), PolicyRenderError> {
    match identity {
        ResolvedEndpointIdentity::Local {
            policy_id,
            entry_id,
        } => write!(
            output,
            "local(policy={}, entry={})",
            escape_terminal_text(policy_id.as_str()),
            escape_terminal_text(entry_id.as_str()),
        ),
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => write!(
            output,
            "catalog(name={}, version={}, hash={}, entry={})",
            escape_terminal_text(catalog.name.as_str()),
            catalog.version,
            catalog.semantic_hash,
            escape_terminal_text(entry_id.as_str()),
        ),
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => write!(
            output,
            "match(endpoint={})",
            escape_terminal_text(endpoint_id.as_str()),
        ),
    }
    .map_err(map_io_error)
}

fn write_optional_stable_identity<W: Write>(
    output: &mut BoundedWriter<W>,
    identity: Option<&StableSemanticIdentity>,
) -> Result<(), PolicyRenderError> {
    let Some(identity) = identity else {
        return write!(output, "unavailable").map_err(map_io_error);
    };
    write!(
        output,
        "{}:{}:{}:{}",
        escape_terminal_text(identity.namespace()),
        escape_terminal_text(identity.path().as_str()),
        identity.derivation().as_str(),
        escape_terminal_text(identity.semantic_key()),
    )
    .map_err(map_io_error)
}

fn write_classification<W: Write>(
    output: &mut BoundedWriter<W>,
    classification: &FindingClassification,
) -> Result<(), PolicyRenderError> {
    let FindingClassification::Classified { broad, refinements } = classification else {
        return writeln!(output, "  classification: unclassified").map_err(map_io_error);
    };
    write!(
        output,
        "  classification: {} {}",
        escape_terminal_text(broad.taxonomy()),
        escape_terminal_text(broad.identifier()),
    )
    .map_err(map_io_error)?;
    if let Some(name) = broad.name() {
        write!(output, " ({})", escape_terminal_text(name)).map_err(map_io_error)?;
    }
    writeln!(output).map_err(map_io_error)?;
    write_classification_provenance(output, "    provenance", broad.provenance())?;
    for refinement in refinements {
        write!(
            output,
            "    refinement: {} {}",
            escape_terminal_text(refinement.taxonomy()),
            escape_terminal_text(refinement.identifier()),
        )
        .map_err(map_io_error)?;
        if let Some(name) = refinement.name() {
            write!(output, " ({})", escape_terminal_text(name)).map_err(map_io_error)?;
        }
        writeln!(output).map_err(map_io_error)?;
        write_classification_provenance(output, "      provenance", refinement.provenance())?;
    }
    Ok(())
}

fn write_classification_provenance<W: Write>(
    output: &mut BoundedWriter<W>,
    label: &str,
    provenance: &ClassificationProvenance,
) -> Result<(), PolicyRenderError> {
    write!(output, "{label}: ").map_err(map_io_error)?;
    match provenance {
        ClassificationProvenance::PolicyFallback => {
            writeln!(output, "policy fallback").map_err(map_io_error)?;
        }
        ClassificationProvenance::PolicyRefinement { refinement_index } => {
            writeln!(output, "policy refinement {refinement_index}").map_err(map_io_error)?;
        }
        ClassificationProvenance::FindingCombination { combination_id } => {
            writeln!(
                output,
                "finding combination {}",
                escape_terminal_text(combination_id.as_str()),
            )
            .map_err(map_io_error)?;
        }
        ClassificationProvenance::AnalysisEvidence {
            adapter,
            evidence_refs,
        } => {
            writeln!(
                output,
                "analysis evidence {}",
                escape_terminal_text(adapter),
            )
            .map_err(map_io_error)?;
            write_text_items(
                output,
                "        evidence",
                evidence_refs.iter().map(|value| value.as_str()),
            )?;
        }
    }
    Ok(())
}

fn write_run_diagnostics<W: Write>(
    output: &mut BoundedWriter<W>,
    run: &PolicyRun,
) -> Result<(), PolicyRenderError> {
    for diagnostic in run.diagnostics() {
        write!(
            output,
            "policy {} diagnostic: [{}; {}] ",
            escape_terminal_text(run.policy_id().as_str()),
            diagnostic_severity(diagnostic.severity()),
            diagnostic_impact(diagnostic.impact()),
        )
        .map_err(map_io_error)?;
        write_policy_diagnostic_code(output, diagnostic.code())?;
        write!(output, ": {}", escape_terminal_text(diagnostic.message())).map_err(map_io_error)?;
        if let Some(primary) = diagnostic.primary() {
            write!(output, " at ").map_err(map_io_error)?;
            write_location(output, primary).map_err(map_io_error)?;
        }
        writeln!(output).map_err(map_io_error)?;
        for related in diagnostic.related() {
            write!(
                output,
                "  diagnostic related {}: ",
                location_relationship(related.relationship()),
            )
            .map_err(map_io_error)?;
            write_location(output, related.location()).map_err(map_io_error)?;
            write_evidence_refs_suffix(output, related.evidence_refs())?;
            writeln!(output).map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_run_completion<W: Write>(
    output: &mut BoundedWriter<W>,
    run: &PolicyRun,
    policy_name: &str,
) -> Result<(), PolicyRenderError> {
    write!(
        output,
        "policy {} ({}): ",
        escape_terminal_text(run.policy_id().as_str()),
        escape_terminal_text(policy_name),
    )
    .map_err(map_io_error)?;
    match run.completion() {
        PolicyRunCompletion::Complete => write!(output, "complete").map_err(map_io_error)?,
        PolicyRunCompletion::Inconclusive { reasons } => {
            write!(output, "inconclusive (").map_err(map_io_error)?;
            for (index, reason) in reasons.iter().enumerate() {
                if index > 0 {
                    write!(output, ", ").map_err(map_io_error)?;
                }
                write!(output, "{}", incomplete_reason(*reason)).map_err(map_io_error)?;
            }
            write!(output, ")").map_err(map_io_error)?;
        }
        PolicyRunCompletion::Unsupported { capability } => {
            write!(output, "unsupported: ").map_err(map_io_error)?;
            write_capability(output, capability)?;
        }
        PolicyRunCompletion::Failed { reasons } => {
            write!(output, "failed (").map_err(map_io_error)?;
            for (index, reason) in reasons.iter().enumerate() {
                if index > 0 {
                    write!(output, ", ").map_err(map_io_error)?;
                }
                write!(output, "{}", failure_reason(*reason)).map_err(map_io_error)?;
            }
            write!(output, ")").map_err(map_io_error)?;
        }
    }
    if run.diagnostics_truncated() {
        write!(output, "; diagnostics truncated").map_err(map_io_error)?;
    }
    writeln!(output, "; non-clean").map_err(map_io_error)
}

fn write_capability<W: Write>(
    output: &mut BoundedWriter<W>,
    capability: &PolicyCapability,
) -> Result<(), PolicyRenderError> {
    match capability {
        PolicyCapability::TaintEvaluation => {
            write!(output, "taint policy compilation").map_err(map_io_error)?;
        }
        PolicyCapability::TypestateEvaluation => {
            write!(output, "typestate policy compilation").map_err(map_io_error)?;
        }
        PolicyCapability::QueryFeature { language, feature } => {
            write!(
                output,
                "query feature {}:{}",
                escape_terminal_text(language),
                escape_terminal_text(feature),
            )
            .map_err(map_io_error)?;
        }
    }
    Ok(())
}

fn write_summary<W: Write>(
    output: &mut BoundedWriter<W>,
    report: &PolicyReportDocument,
) -> Result<(), PolicyRenderError> {
    let finding_count = report.runs().iter().fold(0_usize, |total, run| {
        total.saturating_add(run.findings().len())
    });
    let mut complete = 0_usize;
    let mut inconclusive = 0_usize;
    let mut unsupported = 0_usize;
    let mut failed = 0_usize;
    for run in report.runs() {
        match run.completion() {
            PolicyRunCompletion::Complete => complete = complete.saturating_add(1),
            PolicyRunCompletion::Inconclusive { .. } => {
                inconclusive = inconclusive.saturating_add(1);
            }
            PolicyRunCompletion::Unsupported { .. } => {
                unsupported = unsupported.saturating_add(1);
            }
            PolicyRunCompletion::Failed { .. } => failed = failed.saturating_add(1),
        }
    }

    write!(
        output,
        "summary: {finding_count} finding{}",
        plural_suffix(finding_count)
    )
    .map_err(map_io_error)?;
    if report.runs().is_empty() {
        write!(output, "; 0 policy runs").map_err(map_io_error)?;
    } else {
        write_run_count(output, complete, "complete")?;
        write_run_count(output, inconclusive, "inconclusive")?;
        write_run_count(output, unsupported, "unsupported")?;
        write_run_count(output, failed, "failed")?;
    }

    let all_complete = complete == report.runs().len()
        && report.diagnostics().is_empty()
        && !report.diagnostics_truncated();
    if all_complete && finding_count == 0 {
        write!(output, "; clean").map_err(map_io_error)?;
    } else if !all_complete {
        write!(output, "; non-clean").map_err(map_io_error)?;
    }
    writeln!(output).map_err(map_io_error)
}

fn write_run_count<W: Write>(
    output: &mut BoundedWriter<W>,
    count: usize,
    state: &str,
) -> Result<(), PolicyRenderError> {
    if count > 0 {
        write!(
            output,
            "; {count} {state} policy run{}",
            plural_suffix(count)
        )
        .map_err(map_io_error)?;
    }
    Ok(())
}

fn write_location<W: Write>(
    output: &mut BoundedWriter<W>,
    location: &PolicySourceLocation,
) -> io::Result<()> {
    write!(output, "{}", escape_terminal_text(location.path()))?;
    if let Some(region) = location.region() {
        write!(output, ":{}:{}", region.start_line(), region.start_column())?;
    }
    Ok(())
}

/// Render untrusted analyzer, filesystem, or operational text without letting
/// control or bidirectional-control characters affect terminal output.
pub fn escape_terminal_text(value: &str) -> EscapedTerminalText<'_> {
    EscapedTerminalText(value)
}

/// Display wrapper returned by [`escape_terminal_text`].
pub struct EscapedTerminalText<'a>(&'a str);

impl fmt::Display for EscapedTerminalText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut run_start = 0;
        for (index, character) in self.0.char_indices() {
            if should_escape_text_character(character) {
                formatter.write_str(&self.0[run_start..index])?;
                write!(formatter, "\\u{{{:X}}}", u32::from(character))?;
                run_start = index + character.len_utf8();
            }
        }
        formatter.write_str(&self.0[run_start..])
    }
}

const fn identity_stability(value: FindingIdentityStability) -> &'static str {
    match value {
        FindingIdentityStability::Strong => "strong",
        FindingIdentityStability::Weak => "weak",
    }
}

const fn policy_level(value: PolicyLevel) -> &'static str {
    match value {
        PolicyLevel::Note => "note",
        PolicyLevel::Warning => "warning",
        PolicyLevel::Error => "error",
    }
}

const fn endpoint_role(value: EndpointRole) -> &'static str {
    match value {
        EndpointRole::Source => "source",
        EndpointRole::Sink => "sink",
    }
}

const fn directory_scope(value: DirectoryScope) -> &'static str {
    match value {
        DirectoryScope::Direct => "direct",
        DirectoryScope::Recursive => "recursive",
    }
}

const fn taint_trust_boundary(value: TaintTrustBoundary) -> &'static str {
    match value {
        TaintTrustBoundary::External => "external",
        TaintTrustBoundary::Internal => "internal",
        TaintTrustBoundary::SameTrustZone => "same_trust_zone",
    }
}

const fn taint_system_entry(value: TaintSystemEntry) -> &'static str {
    match value {
        TaintSystemEntry::VulnerableSystemNetworkStack => "vulnerable_system_network_stack",
        TaintSystemEntry::DownloadedArtifact => "downloaded_artifact",
        TaintSystemEntry::LocalInput => "local_input",
        TaintSystemEntry::AdjacentNetwork => "adjacent_network",
        TaintSystemEntry::Physical => "physical",
    }
}

const fn schema_version_origin(value: SchemaVersionOrigin) -> &'static str {
    match value {
        SchemaVersionOrigin::Explicit => "explicit",
        SchemaVersionOrigin::ImplicitCompatible => "implicit_compatible",
        SchemaVersionOrigin::ReferencedDocumentExplicit => "referenced_document_explicit",
    }
}

const fn cvss_version(value: CvssVersion) -> &'static str {
    match value {
        CvssVersion::V4_0 => "4.0",
    }
}

const fn cvss_evidence_basis(value: CvssEvidenceBasis) -> &'static str {
    match value {
        CvssEvidenceBasis::StaticWitness => "static_witness",
        CvssEvidenceBasis::PolicyAssertion => "policy_assertion",
        CvssEvidenceBasis::EnvironmentProfile => "environment_profile",
        CvssEvidenceBasis::ThreatFeed => "threat_feed",
        CvssEvidenceBasis::AnalystOverride => "analyst_override",
    }
}

const fn cvss_evidence_scope(value: CvssEvidenceScope) -> &'static str {
    match value {
        CvssEvidenceScope::Global => "global",
        CvssEvidenceScope::System {
            system: CvssSystemScope::VulnerableSystem,
        } => "vulnerable_system",
        CvssEvidenceScope::System {
            system: CvssSystemScope::SubsequentSystem,
        } => "subsequent_system",
    }
}

const fn query_result_kind(value: &PolicyQueryResultRef) -> &'static str {
    match value {
        PolicyQueryResultRef::StructuralMatch { .. } => "structural_match",
        PolicyQueryResultRef::Declaration { .. } => "declaration",
        PolicyQueryResultRef::File { .. } => "file",
        PolicyQueryResultRef::ReferenceSite { .. } => "reference_site",
        PolicyQueryResultRef::CallSite { .. } => "call_site",
        PolicyQueryResultRef::ExpressionSite { .. } => "expression_site",
        PolicyQueryResultRef::ReceiverAnalysis { .. } => "receiver_analysis",
        PolicyQueryResultRef::Unsupported { .. } => "unsupported",
    }
}

const fn endpoint_phase(value: EndpointObservationPhase) -> &'static str {
    match value {
        EndpointObservationPhase::AtMatch => "at_match",
        EndpointObservationPhase::BeforeCall => "before_call",
        EndpointObservationPhase::AfterNormalReturn => "after_normal_return",
        EndpointObservationPhase::AfterExceptionalReturn => "after_exceptional_return",
    }
}

const fn semantic_event(value: PolicySemanticEvent) -> &'static str {
    match value {
        PolicySemanticEvent::NormalProcedureExit { .. } => "normal_procedure_exit/analysis_root",
        PolicySemanticEvent::ExceptionalProcedureExit { .. } => {
            "exceptional_procedure_exit/analysis_root"
        }
    }
}

fn certainty_reason(value: &CertaintyReason) -> &str {
    match value {
        CertaintyReason::AmbiguousReceiver => "ambiguous_receiver",
        CertaintyReason::AmbiguousDispatch => "ambiguous_dispatch",
        CertaintyReason::NameBasedResolution => "name_based_resolution",
        CertaintyReason::MultipleCandidateDeclarations => "multiple_candidate_declarations",
        CertaintyReason::AnalyzerAmbiguity { code } => code.as_str(),
    }
}

fn proof_reason(value: &ProofReason) -> &str {
    match value {
        ProofReason::DirectStructuralMatch => "direct_structural_match",
        ProofReason::ResolvedDeclaration => "resolved_declaration",
        ProofReason::ResolvedReference => "resolved_reference",
        ProofReason::ExactCallTarget => "exact_call_target",
        ProofReason::DataflowWitness => "dataflow_witness",
        ProofReason::TypestateWitness => "typestate_witness",
        ProofReason::AmbiguousTarget => "ambiguous_target",
        ProofReason::PartialWitness => "partial_witness",
        ProofReason::AnalyzerEvidence { code } => code.as_str(),
    }
}

const fn analysis_type(value: PolicyAnalysisType) -> &'static str {
    match value {
        PolicyAnalysisType::Match => "match",
        PolicyAnalysisType::Taint => "taint",
        PolicyAnalysisType::Typestate => "typestate",
    }
}

const fn query_proof(value: PolicyQueryProof) -> &'static str {
    match value {
        PolicyQueryProof::Exact => "exact",
        PolicyQueryProof::Resolved => "resolved",
        PolicyQueryProof::NameBased => "name_based",
        PolicyQueryProof::Ambiguous => "ambiguous",
        PolicyQueryProof::Unknown => "unknown",
    }
}

const fn finding_severity(value: FindingSeverity) -> &'static str {
    match value {
        FindingSeverity::Unrated => "unrated",
        FindingSeverity::Note => "note",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

const fn diagnostic_severity(value: PolicyDiagnosticSeverity) -> &'static str {
    match value {
        PolicyDiagnosticSeverity::Note => "note",
        PolicyDiagnosticSeverity::Warning => "warning",
        PolicyDiagnosticSeverity::Error => "error",
    }
}

const fn diagnostic_impact(value: PolicyDiagnosticImpact) -> &'static str {
    match value {
        PolicyDiagnosticImpact::Advisory => "advisory",
        PolicyDiagnosticImpact::FindingPartial => "finding_partial",
        PolicyDiagnosticImpact::RunIncomplete => "run_incomplete",
        PolicyDiagnosticImpact::RunUnsupported => "run_unsupported",
        PolicyDiagnosticImpact::RunFailed => "run_failed",
    }
}

const fn certainty(value: &FindingCertainty) -> &'static str {
    match value {
        FindingCertainty::Definite => "definite",
        FindingCertainty::Possible { .. } => "possible",
    }
}

const fn completeness(value: &FindingCompleteness) -> &'static str {
    match value {
        FindingCompleteness::Complete => "complete",
        FindingCompleteness::Partial { .. } => "partial",
    }
}

const fn match_result_domain(value: MatchResultDomain) -> &'static str {
    match value {
        MatchResultDomain::StructuralMatch => "structural_match",
        MatchResultDomain::Declaration => "declaration",
        MatchResultDomain::File => "file",
        MatchResultDomain::ReferenceSite => "reference_site",
        MatchResultDomain::CallSite => "call_site",
        MatchResultDomain::ExpressionSite => "expression_site",
    }
}

const fn location_relationship(value: PolicyLocationRelationship) -> &'static str {
    match value {
        PolicyLocationRelationship::Source => "source",
        PolicyLocationRelationship::Sink => "sink",
        PolicyLocationRelationship::Origin => "origin",
        PolicyLocationRelationship::Evidence => "evidence",
        PolicyLocationRelationship::WitnessStep => "witness_step",
        PolicyLocationRelationship::Declaration => "declaration",
        PolicyLocationRelationship::CallTarget => "call_target",
    }
}

const fn witness_step_kind(value: WitnessStepKind) -> &'static str {
    match value {
        WitnessStepKind::Source => "source",
        WitnessStepKind::Propagation => "propagation",
        WitnessStepKind::Call => "call",
        WitnessStepKind::Return => "return",
        WitnessStepKind::Sanitizer => "sanitizer",
        WitnessStepKind::Transform => "transform",
        WitnessStepKind::Transition => "transition",
        WitnessStepKind::Violation => "violation",
    }
}

const fn proof_state(value: ProofState) -> &'static str {
    match value {
        ProofState::Proven => "proven",
        ProofState::Unproven => "unproven",
        ProofState::Ambiguous => "ambiguous",
    }
}

const fn cvss_nomenclature(value: CvssNomenclature) -> &'static str {
    match value {
        CvssNomenclature::B => "B",
        CvssNomenclature::BT => "BT",
        CvssNomenclature::BE => "BE",
        CvssNomenclature::BTE => "BTE",
    }
}

const fn cvss_severity(value: CvssSeverity) -> &'static str {
    match value {
        CvssSeverity::None => "None",
        CvssSeverity::Low => "Low",
        CvssSeverity::Medium => "Medium",
        CvssSeverity::High => "High",
        CvssSeverity::Critical => "Critical",
    }
}

const fn incomplete_reason(value: PolicyIncompleteReason) -> &'static str {
    match value {
        PolicyIncompleteReason::Cancelled => "cancelled",
        PolicyIncompleteReason::QueryResultLimit => "query_result_limit",
        PolicyIncompleteReason::BatchFindingLimit => "batch_finding_limit",
        PolicyIncompleteReason::ScannedFileBudget => "scanned_file_budget",
        PolicyIncompleteReason::SourceByteBudget => "source_byte_budget",
        PolicyIncompleteReason::FactNodeBudget => "fact_node_budget",
        PolicyIncompleteReason::PipelineRowBudget => "pipeline_row_budget",
        PolicyIncompleteReason::ImportGraphBudget => "import_graph_budget",
        PolicyIncompleteReason::ReferenceCandidateBudget => "reference_candidate_budget",
        PolicyIncompleteReason::PartialDiscovery => "partial_discovery",
        PolicyIncompleteReason::CapabilityIncomplete => "capability_incomplete",
        PolicyIncompleteReason::EndpointDominanceUndecidable => "endpoint_dominance_undecidable",
        PolicyIncompleteReason::StableAnchorUnavailable => "stable_anchor_unavailable",
        PolicyIncompleteReason::ReportRetentionBudget => "report_retention_budget",
        PolicyIncompleteReason::CvssVariantBudget => "cvss_variant_budget",
        PolicyIncompleteReason::ProjectionScenarioMembershipBudget => {
            "projection_scenario_membership_budget"
        }
        PolicyIncompleteReason::OrganizationalRiskOverlayBudget => {
            "organizational_risk_overlay_budget"
        }
    }
}

const fn failure_reason(value: PolicyFailureReason) -> &'static str {
    match value {
        PolicyFailureReason::InvalidExecutionPlan => "invalid_execution_plan",
        PolicyFailureReason::WorkspaceSnapshotUnavailable => "workspace_snapshot_unavailable",
        PolicyFailureReason::SourceReadFailed => "source_read_failed",
        PolicyFailureReason::WorkspaceIo => "workspace_io",
        PolicyFailureReason::AmbiguousEndpointDominance => "ambiguous_endpoint_dominance",
        PolicyFailureReason::AmbiguousTypestateBinding => "ambiguous_typestate_binding",
        PolicyFailureReason::ConflictingOrganizationalRiskOverlay => {
            "conflicting_organizational_risk_overlay"
        }
        PolicyFailureReason::InternalInvariant => "internal_invariant",
    }
}

const fn finding_incomplete_reason(value: FindingIncompleteReason) -> &'static str {
    match value {
        FindingIncompleteReason::QueryProvenanceTruncated => "query_provenance_truncated",
        FindingIncompleteReason::RelatedLocationsTruncated => "related_locations_truncated",
        FindingIncompleteReason::OriginsTruncated => "origins_truncated",
        FindingIncompleteReason::SourceScenariosTruncated => "source_scenarios_truncated",
        FindingIncompleteReason::TypestateScenariosTruncated => "typestate_scenarios_truncated",
        FindingIncompleteReason::WitnessTruncated => "witness_truncated",
        FindingIncompleteReason::EvidenceTruncated => "evidence_truncated",
        FindingIncompleteReason::ProofPartial => "proof_partial",
        FindingIncompleteReason::StableAnchorWeak => "stable_anchor_weak",
    }
}

fn report_diagnostic_code(value: super::super::PolicyReportDiagnosticCode) -> &'static str {
    use super::super::PolicyReportDiagnosticCode as Code;
    match value {
        Code::PolicyLoadFailed => "policy-load-failed",
        Code::PolicyParseFailed => "policy-parse-failed",
        Code::PolicyValidationFailed => "policy-validation-failed",
        Code::EndpointParseFailed => "endpoint-parse-failed",
        Code::EndpointValidationFailed => "endpoint-validation-failed",
        Code::NotExecutableEndpoint => "not-executable-endpoint",
        Code::DuplicatePolicyId => "duplicate-policy-id",
        Code::DuplicateEndpointId => "duplicate-endpoint-id",
        Code::PolicyCountLimit => "policy-count-limit",
        Code::EndpointCountLimit => "endpoint-count-limit",
        Code::MatchDirectoryLimit => "match-directory-limit",
        Code::MatchDirectoryChangedDuringLoad => "match-directory-changed-during-load",
        Code::MatchDirectoryManifestMismatch => "match-directory-manifest-mismatch",
        Code::NonEndpointInMatchDirectory => "non-endpoint-in-match-directory",
        Code::EndpointMissingOrMismatchedTaintSemantics => {
            "endpoint-missing-or-mismatched-taint-semantics"
        }
        Code::AmbiguousCombinationPrecedence => "ambiguous-combination-precedence",
        Code::UnsupportedPolicySchemaVersion => "unsupported-policy-schema-version",
        Code::UnsupportedRqlSchemaVersion => "unsupported-rql-schema-version",
        Code::ConflictingRqlSchemaVersion => "conflicting-rql-schema-version",
        Code::ExplicitPolicySchemaVersionRequired => "explicit-policy-schema-version-required",
        Code::ExplicitRqlSchemaVersionRequired => "explicit-rql-schema-version-required",
    }
}

fn write_policy_diagnostic_code<W: Write>(
    output: &mut BoundedWriter<W>,
    value: &super::super::PolicyDiagnosticCode,
) -> Result<(), PolicyRenderError> {
    use super::super::PolicyDiagnosticCode as Code;
    let label = match value {
        Code::CodeQuery { code } => {
            return write!(output, "code_query/{}", code.as_str()).map_err(map_io_error);
        }
        Code::UnsupportedAnalysis => "unsupported_analysis",
        Code::StableAnchorUnavailable => "stable_anchor_unavailable",
        Code::EndpointDominanceUndecidable => "endpoint_dominance_undecidable",
        Code::EvaluationFailure => "evaluation_failure",
        Code::BatchFindingLimit => "batch_finding_limit",
        Code::ReportRetentionBudget => "report_retention_budget",
        Code::CvssVariantBudget => "cvss_variant_budget",
        Code::ProjectionScenarioMembershipBudget => "projection_scenario_membership_budget",
        Code::OrganizationalRiskOverlayBudget => "organizational_risk_overlay_budget",
    };
    write!(output, "{label}").map_err(map_io_error)
}

const fn plural_suffix(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

const fn plural_suffix_u64(count: u64) -> &'static str {
    if count == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::{
        CvssAssessmentProvenance, CvssAssessmentVariant, CvssBaseMetric, CvssEvidenceBasis,
        CvssEvidenceContentHash, CvssEvidenceSetHash, CvssMetric, CvssMetricEvidence,
        CvssMetricValue, CvssMetricValueToken, CvssUnscoredReason, CvssVersion, EvidenceRef,
        OpaqueFindingKey, PolicyDiagnosticCode, PolicyOverlayScope, SourceScenarioSetHash,
        SourceSliceHash, VulnerabilityIdentity,
    };
    use crate::analyzer::semantic::WorkspaceRelativePath;
    use crate::analyzer::structural::CodeQueryDiagnosticCode;

    #[test]
    fn terminal_escape_is_visible_and_cannot_create_lines_or_ansi_sequences() {
        let rendered =
            escape_terminal_text("a\n\t\u{001B}[31m\u{007F}\u{0085}\u{202E}\u{2066}z").to_string();
        assert_eq!(
            rendered,
            r"a\u{A}\u{9}\u{1B}[31m\u{7F}\u{85}\u{202E}\u{2066}z"
        );
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\u{001B}'));
    }

    #[test]
    fn call_and_reference_summaries_retain_relational_identities_and_proof() {
        let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
        let callee_identity =
            StableSemanticIdentity::catalog_entry("rust", path, "crate::callee").unwrap();
        let call = PolicyQueryResultRef::CallSite {
            location: PolicySourceLocation::span(
                WorkspaceRelativePath::new("src/app.rs").unwrap(),
                super::super::super::PolicyByteSpan::new(2, 8).unwrap(),
                super::super::super::PolicyDisplayRegion::new(1, 3, 1, 9).unwrap(),
            ),
            caller_fq_name: "crate::caller".to_string(),
            caller_identity: None,
            callee_fq_name: "crate::callee".to_string(),
            callee_identity: Some(callee_identity),
            proof: PolicyQueryProof::Resolved,
        };
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_query_result_detail(&mut rendered, &call).unwrap();
        let rendered = String::from_utf8(rendered.inner).unwrap();
        assert_eq!(
            rendered,
            " call crate::caller [identity unavailable] -> crate::callee [identity rust:src/app.rs:catalog_entry:crate::callee]; proof resolved"
        );

        let reference = PolicyQueryResultRef::ReferenceSite {
            location: PolicySourceLocation::span(
                WorkspaceRelativePath::new("src/app.rs").unwrap(),
                super::super::super::PolicyByteSpan::new(2, 8).unwrap(),
                super::super::super::PolicyDisplayRegion::new(1, 3, 1, 9).unwrap(),
            ),
            target_fq_name: "crate::target".to_string(),
            target_identity: None,
            usage_kind: Some("read".to_string()),
            proof: PolicyQueryProof::Ambiguous,
        };
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_query_result_detail(&mut rendered, &reference).unwrap();
        assert_eq!(
            String::from_utf8(rendered.inner).unwrap(),
            " target crate::target; target identity unavailable; usage read; proof ambiguous"
        );
    }

    fn cvss_metric_evidence(metric: CvssBaseMetric, byte: u8) -> CvssMetricEvidence {
        let token = match metric {
            CvssBaseMetric::Ac => CvssMetricValueToken::L,
            CvssBaseMetric::At | CvssBaseMetric::Av | CvssBaseMetric::Pr | CvssBaseMetric::Ui => {
                CvssMetricValueToken::N
            }
            CvssBaseMetric::Vc
            | CvssBaseMetric::Vi
            | CvssBaseMetric::Va
            | CvssBaseMetric::Sc
            | CvssBaseMetric::Si
            | CvssBaseMetric::Sa => CvssMetricValueToken::H,
        };
        let typed_metric = CvssMetric::Base { metric };
        CvssMetricEvidence::try_new(
            typed_metric,
            CvssMetricValue::try_new(typed_metric, token).unwrap(),
            CvssEvidenceBasis::PolicyAssertion,
            vec![EvidenceRef::try_new("human", metric.first_label()).unwrap()],
            "Verified policy assertion".to_string(),
            vec!["Deployment matches the policy model".to_string()],
            "bifrost-policy".to_string(),
            None,
            metric.required_scope(),
            CvssEvidenceContentHash::from_bytes([byte; 32]),
        )
        .unwrap()
    }

    fn cvss_provenance() -> CvssAssessmentProvenance {
        CvssAssessmentProvenance::try_new(
            "bifrost.cvss-v4".to_string(),
            Vec::new(),
            vec![PolicyOverlayScope::AllFindings],
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn structured_cvss_details_preserve_scored_and_unscored_evidence() {
        let metrics = [
            CvssBaseMetric::Av,
            CvssBaseMetric::Ac,
            CvssBaseMetric::At,
            CvssBaseMetric::Pr,
            CvssBaseMetric::Ui,
            CvssBaseMetric::Vc,
            CvssBaseMetric::Vi,
            CvssBaseMetric::Va,
            CvssBaseMetric::Sc,
            CvssBaseMetric::Si,
            CvssBaseMetric::Sa,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, metric)| cvss_metric_evidence(metric, u8::try_from(index + 1).unwrap()))
        .collect();
        let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H";
        let component = CvssComponentResult::try_new(
            CvssNomenclature::B,
            vector.to_string(),
            10.0,
            CvssSeverity::Critical,
        )
        .unwrap();
        let scored = CvssAssessment::scored(
            CvssVersion::V4_0,
            CvssNomenclature::B,
            vector.to_string(),
            vec![component],
            metrics,
            cvss_provenance(),
        )
        .unwrap();
        let scored = CvssAssessmentVariant::try_new(
            VulnerabilityIdentity::from_bytes([1; 32]),
            Vec::new(),
            false,
            0,
            SourceScenarioSetHash::from_bytes([2; 32]),
            Vec::new(),
            false,
            scored,
        )
        .unwrap();
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_cvss_variant_detail(&mut rendered, &scored).unwrap();
        let rendered = String::from_utf8(rendered.inner).unwrap();
        assert!(rendered.contains("    scored assessment: CVSS 4.0 B\n"));
        assert!(rendered.contains(&format!("      vector: {vector}\n")));
        assert_eq!(rendered.matches("      metric: ").count(), 11);
        assert!(rendered.contains(" (policy_assertion, vulnerable_system; hash "));
        assert!(rendered.contains("        rationale: Verified policy assertion\n"));
        assert!(rendered.contains("        evidence: human:"));
        assert!(rendered.contains("        assumption: Deployment matches the policy model\n"));
        assert!(rendered.contains("        assessor or tool: bifrost-policy\n"));
        assert!(rendered.contains("      reducer: bifrost.cvss-v4\n"));
        assert!(rendered.contains("      overlay scope: all findings\n"));
        assert!(!rendered.contains("detail: {"));

        let unscored = CvssAssessment::unscored(
            CvssVersion::V4_0,
            Vec::new(),
            vec![CvssBaseMetric::Av],
            vec![
                CvssUnscoredReason::MissingBaseEvidence,
                CvssUnscoredReason::conflicting_metric_evidence(
                    CvssMetric::Base {
                        metric: CvssBaseMetric::Av,
                    },
                    CvssEvidenceSetHash::from_bytes([3; 32]),
                    vec![EvidenceRef::try_new("human", "conflict").unwrap()],
                    false,
                    0,
                )
                .unwrap(),
            ],
            cvss_provenance(),
        )
        .unwrap();
        let unscored = CvssAssessmentVariant::try_new(
            VulnerabilityIdentity::from_bytes([4; 32]),
            Vec::new(),
            false,
            0,
            SourceScenarioSetHash::from_bytes([5; 32]),
            Vec::new(),
            false,
            unscored,
        )
        .unwrap();
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_cvss_variant_detail(&mut rendered, &unscored).unwrap();
        let rendered = String::from_utf8(rendered.inner).unwrap();
        assert!(rendered.contains("    unscored assessment: CVSS 4.0\n"));
        assert!(rendered.contains("      missing base metric: AV\n"));
        assert!(rendered.contains("      unscored reason: missing base evidence\n"));
        assert!(rendered.contains("      unscored reason: conflicting AV evidence (set "));
        assert!(rendered.contains("        conflicting evidence: human:conflict\n"));
        assert!(rendered.contains("      reducer: bifrost.cvss-v4\n"));
        assert!(!rendered.contains("detail: {"));
    }

    #[test]
    fn analyzer_prose_and_paths_use_the_terminal_escape_convention() {
        let result = PolicyQueryResultRef::CallSite {
            location: PolicySourceLocation::artifact(
                WorkspaceRelativePath::new("src/\u{0085}\u{202E}.rs").unwrap(),
            ),
            caller_fq_name: "caller\n\u{001B}\u{2066}".to_string(),
            caller_identity: None,
            callee_fq_name: "callee\u{202E}".to_string(),
            callee_identity: None,
            proof: PolicyQueryProof::Ambiguous,
        };
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_query_result_line(&mut rendered, "  analyzer result", &result).unwrap();
        let rendered = String::from_utf8(rendered.inner).unwrap();
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.contains(r"caller\u{A}\u{1B}\u{2066}"));
        assert!(rendered.contains(r"callee\u{202E}"));
        assert!(rendered.contains(r"src/\u{85}\u{202E}.rs"));
        assert!(!rendered.contains('\u{001B}'));
        assert!(!rendered.contains('\u{0085}'));
        assert!(!rendered.contains('\u{202E}'));
        assert!(!rendered.contains('\u{2066}'));
    }

    #[test]
    fn match_anchor_details_distinguish_strong_and_weak_inputs() {
        let strong = MatchFindingAnchor::strong(
            MatchResultDomain::StructuralMatch,
            WorkspaceRelativePath::new("src/app.rs").unwrap(),
            None,
            Some(SourceSliceHash::from_bytes([7; 32])),
            2,
        )
        .unwrap();
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_match_anchor(&mut rendered, &strong).unwrap();
        let rendered = String::from_utf8(rendered.inner).unwrap();
        assert!(rendered.starts_with("  match anchor: strong structural_match src/app.rs\n"));
        assert!(rendered.contains("    semantic owner: unavailable\n"));
        assert!(rendered.contains(&format!(
            "    selected source: {}\n",
            SourceSliceHash::from_bytes([7; 32])
        )));
        assert!(rendered.ends_with("    occurrence ordinal: 2\n"));

        let weak = MatchFindingAnchor::weak(
            MatchResultDomain::CallSite,
            WorkspaceRelativePath::new("src/app.rs").unwrap(),
            OpaqueFindingKey::try_new("adapter", "snapshot-key").unwrap(),
        );
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_match_anchor(&mut rendered, &weak).unwrap();
        assert_eq!(
            String::from_utf8(rendered.inner).unwrap(),
            "  match anchor: weak call_site src/app.rs\n    typed key: adapter:snapshot-key\n"
        );
    }

    #[test]
    fn witness_evidence_and_nested_query_diagnostic_codes_are_explicit() {
        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_evidence_refs_suffix(
            &mut rendered,
            &[EvidenceRef::try_new("witness", "step-1").unwrap()],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(rendered.inner).unwrap(),
            " [evidence witness:step-1]"
        );

        let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
        write_policy_diagnostic_code(
            &mut rendered,
            &PolicyDiagnosticCode::CodeQuery {
                code: CodeQueryDiagnosticCode::ResultLimitReached,
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(rendered.inner).unwrap(),
            "code_query/result_limit_reached"
        );
    }

    #[test]
    fn all_finding_incomplete_reason_spellings_are_stable() {
        let reasons = [
            FindingIncompleteReason::QueryProvenanceTruncated,
            FindingIncompleteReason::RelatedLocationsTruncated,
            FindingIncompleteReason::OriginsTruncated,
            FindingIncompleteReason::SourceScenariosTruncated,
            FindingIncompleteReason::TypestateScenariosTruncated,
            FindingIncompleteReason::WitnessTruncated,
            FindingIncompleteReason::EvidenceTruncated,
            FindingIncompleteReason::ProofPartial,
            FindingIncompleteReason::StableAnchorWeak,
        ];
        assert!(
            reasons
                .into_iter()
                .all(|reason| !finding_incomplete_reason(reason).is_empty())
        );
    }

    #[test]
    fn missing_named_cvss_component_is_a_render_error_not_a_panic() {
        assert!(matches!(
            named_cvss_component(&[], CvssNomenclature::B),
            Err(PolicyRenderError::InvalidCanonicalReport { .. })
        ));
    }

    #[test]
    fn unsupported_analysis_capability_phrases_are_stable() {
        let cases = [
            (
                PolicyCapability::TaintEvaluation,
                "taint policy compilation",
            ),
            (
                PolicyCapability::TypestateEvaluation,
                "typestate policy compilation",
            ),
        ];

        for (capability, expected) in cases {
            let mut rendered = BoundedWriter::new(Vec::new(), usize::MAX);
            write_capability(&mut rendered, &capability).unwrap();
            assert_eq!(String::from_utf8(rendered.inner).unwrap(), expected);
        }
    }
}
