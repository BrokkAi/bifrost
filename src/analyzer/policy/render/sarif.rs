//! Deterministic, bounded SARIF 2.1.0 rendering for canonical policy reports.

use std::fmt;
use std::io::Write;

use serde::ser::{Error as _, SerializeSeq};
use serde::{Serialize, Serializer};

use super::{
    BoundedWriter, CanonicalJsonFormatter, PolicyRenderError, ensure_supported_schema,
    map_io_error, map_json_error,
};
use crate::analyzer::policy::{
    BoundedWitness, FindingCertainty, FindingCompleteness, FindingIdentityStability,
    FindingSeverity, OrganizationalRiskAssessment, PolicyAnalysisType, PolicyDiagnostic,
    PolicyDiagnosticSeverity, PolicyDisplayRegion, PolicyFinding, PolicyFindingEvidence,
    PolicyLevel, PolicyReportDiagnostic, PolicyReportDocument, PolicyRuleDescriptor, PolicyRun,
    PolicyRunCompletion, PolicySemanticHash, PolicySeveritySpec, PolicySourceLocation,
    PolicyWorkReport, ProofMetadata, RelatedPolicyLocation, WitnessStep, WitnessStepKind,
};

const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const SOURCE_ROOT_ID: &str = "SRCROOT";

/// Stable producer metadata for one SARIF log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SarifToolIdentity {
    name: String,
    version: Option<String>,
    information_uri: Option<String>,
}

impl SarifToolIdentity {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            information_uri: None,
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_information_uri(mut self, information_uri: impl Into<String>) -> Self {
        self.information_uri = Some(information_uri.into());
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn information_uri(&self) -> Option<&str> {
        self.information_uri.as_deref()
    }

    fn validate(&self) -> Result<(), PolicyRenderError> {
        if self.name.trim().is_empty() {
            return Err(PolicyRenderError::InvalidCanonicalReport {
                detail: "the SARIF tool name must not be empty",
            });
        }
        if self
            .version
            .as_ref()
            .is_some_and(|version| version.is_empty())
        {
            return Err(PolicyRenderError::InvalidCanonicalReport {
                detail: "the SARIF tool version must not be empty when present",
            });
        }
        if self
            .information_uri
            .as_deref()
            .is_some_and(|uri| normalize_absolute_uri(uri).is_none())
        {
            return Err(PolicyRenderError::InvalidCanonicalReport {
                detail: "the SARIF tool information URI must be an absolute URI",
            });
        }
        Ok(())
    }
}

impl Default for SarifToolIdentity {
    fn default() -> Self {
        Self::new("Bifrost")
            .with_version(env!("CARGO_PKG_VERSION"))
            .with_information_uri(env!("CARGO_PKG_HOMEPAGE"))
    }
}

/// Serialize one canonical policy report as a single bounded SARIF run.
pub fn write_policy_sarif<W: Write>(
    report: &PolicyReportDocument,
    tool: &SarifToolIdentity,
    output: W,
    max_serialized_bytes: usize,
) -> Result<u64, PolicyRenderError> {
    ensure_supported_schema(report)?;
    tool.validate()?;
    let log = SarifLog::try_from_report(report, tool)?;
    let mut output = BoundedWriter::new(output, max_serialized_bytes);
    let serialized = {
        let mut serializer =
            serde_json::Serializer::with_formatter(&mut output, CanonicalJsonFormatter);
        log.serialize(&mut serializer)
    };
    if let Err(error) = serialized {
        if output.limit_exceeded() {
            return Err(PolicyRenderError::SerializedReportLimit {
                max_serialized_bytes,
            });
        }
        return Err(map_json_error(error, max_serialized_bytes));
    }
    output.flush().map_err(map_io_error)?;
    Ok(output.bytes_written())
}

#[derive(Serialize)]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [SarifRun<'a>; 1],
}

impl<'a> SarifLog<'a> {
    fn try_from_report(
        report: &'a PolicyReportDocument,
        tool: &'a SarifToolIdentity,
    ) -> Result<Self, PolicyRenderError> {
        Ok(Self {
            schema: SARIF_SCHEMA_URI,
            version: SARIF_VERSION,
            runs: [SarifRun::try_from_report(report, tool)?],
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    column_kind: &'static str,
    results: SarifResults<'a>,
    invocations: [SarifInvocation<'a>; 1],
    properties: SarifRunProperties<'a>,
}

impl<'a> SarifRun<'a> {
    fn try_from_report(
        report: &'a PolicyReportDocument,
        tool: &'a SarifToolIdentity,
    ) -> Result<Self, PolicyRenderError> {
        // Validate every join before the serializer can touch the destination,
        // but retain only borrowed views. Sequence serializers below visit the
        // report lazily after the bounded writer has accepted their prefixes.
        for run in report.runs() {
            report
                .rules()
                .iter()
                .position(|rule| {
                    rule.policy_id() == run.policy_id()
                        && rule.policy_hash() == run.policy_hash()
                        && rule.analysis_type() == run.analysis_type()
                })
                .ok_or(PolicyRenderError::InvalidCanonicalReport {
                    detail: "a policy run has no exact rule descriptor",
                })?;
        }

        Ok(Self {
            tool: SarifTool {
                driver: SarifDriver {
                    name: tool.name(),
                    version: tool.version(),
                    information_uri: tool.information_uri(),
                    rules: SarifRules(report.rules()),
                },
            },
            column_kind: "unicodeCodePoints",
            results: SarifResults { report },
            invocations: [SarifInvocation::from_report(report)],
            properties: SarifRunProperties::from_report(report),
        })
    }
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    information_uri: Option<&'a str>,
    rules: SarifRules<'a>,
}

struct SarifRules<'a>(&'a [PolicyRuleDescriptor]);

impl Serialize for SarifRules<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for rule in self.0 {
            sequence.serialize_element(&SarifReportingDescriptor::from_rule(rule))?;
        }
        sequence.end()
    }
}

struct SarifResults<'a> {
    report: &'a PolicyReportDocument,
}

impl Serialize for SarifResults<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let result_count = self
            .report
            .runs()
            .iter()
            .map(|run| run.findings().len())
            .try_fold(0_usize, usize::checked_add)
            .ok_or_else(|| S::Error::custom("SARIF result count overflow"))?;
        let mut sequence = serializer.serialize_seq(Some(result_count))?;
        for run in self.report.runs() {
            let rule_index = self
                .report
                .rules()
                .iter()
                .position(|rule| {
                    rule.policy_id() == run.policy_id()
                        && rule.policy_hash() == run.policy_hash()
                        && rule.analysis_type() == run.analysis_type()
                })
                .ok_or_else(|| S::Error::custom("a policy run has no exact rule descriptor"))?;
            for finding in run.findings() {
                note_sarif_result_visit();
                sequence.serialize_element(&SarifResult::from_finding(finding, run, rule_index))?;
            }
        }
        sequence.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReportingDescriptor<'a> {
    id: &'a str,
    name: &'a str,
    short_description: SarifMessage<'a>,
    full_description: SarifMessage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<&'a str>,
    default_configuration: SarifReportingConfiguration,
    properties: SarifRuleProperties<'a>,
}

impl<'a> SarifReportingDescriptor<'a> {
    fn from_rule(rule: &'a PolicyRuleDescriptor) -> Self {
        let descriptor_text = match rule.message() {
            crate::analyzer::policy::PolicyMessageSpec::Static { text } => text,
            crate::analyzer::policy::PolicyMessageSpec::Generated { .. } => {
                "Selected source can reach selected sink"
            }
        };
        Self {
            id: rule.policy_id().as_str(),
            name: rule.name(),
            short_description: SarifMessage { text: rule.name() },
            full_description: SarifMessage {
                text: rule.description().unwrap_or(descriptor_text),
            },
            help_uri: rule.help_uri(),
            default_configuration: SarifReportingConfiguration {
                level: rule_default_level(rule.severity()),
            },
            properties: SarifRuleProperties {
                tags: rule.tags(),
                descriptor: rule,
            },
        }
    }
}

#[derive(Serialize)]
struct SarifReportingConfiguration {
    level: SarifLevel,
}

#[derive(Serialize)]
struct SarifRuleProperties<'a> {
    tags: &'a [String],
    #[serde(rename = "bifrost.ruleDescriptor")]
    descriptor: &'a PolicyRuleDescriptor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    rule_index: usize,
    message: SarifMessage<'a>,
    level: SarifLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    locations: [SarifLocation<'a>; 1],
    #[serde(skip_serializing_if = "SarifRelatedLocations::is_empty")]
    related_locations: SarifRelatedLocations<'a>,
    #[serde(skip_serializing_if = "SarifCodeFlows::is_empty")]
    code_flows: SarifCodeFlows<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_fingerprints: Option<SarifPartialFingerprints>,
    properties: SarifResultProperties<'a>,
}

impl<'a> SarifResult<'a> {
    fn from_finding(finding: &'a PolicyFinding, run: &'a PolicyRun, rule_index: usize) -> Self {
        let level = finding_level(finding.severity());
        let unrated = finding.severity() == FindingSeverity::Unrated;
        Self {
            rule_id: finding.policy_id().as_str(),
            rule_index,
            message: SarifMessage {
                text: finding.message(),
            },
            level,
            kind: unrated.then_some("informational"),
            locations: [SarifLocation::primary(finding.primary())],
            related_locations: SarifRelatedLocations(finding.related()),
            code_flows: SarifCodeFlows(finding.witnesses()),
            partial_fingerprints: (finding.identity_stability()
                == FindingIdentityStability::Strong)
                .then(|| SarifPartialFingerprints {
                    finding_id: finding.id(),
                }),
            properties: SarifResultProperties {
                finding_id: finding.id(),
                policy_hash: finding.policy_hash(),
                analysis_type: finding.analysis_type(),
                identity_stability: finding.identity_stability(),
                severity: finding.severity(),
                unrated,
                run_completion: run.completion(),
                finding_completeness: finding.completeness(),
                certainty: finding.certainty(),
                classification: finding.classification(),
                evidence: finding.evidence(),
                related_locations_truncated: finding.related_truncated(),
                omitted_related_locations_lower_bound: finding
                    .omitted_related_locations_lower_bound(),
                evidence_refs_truncated: finding.evidence_refs_truncated(),
                omitted_evidence_refs_lower_bound: finding.omitted_evidence_refs_lower_bound(),
                cvss: finding.cvss(),
                organizational_risk: finding.organizational_risk(),
                proof: finding.proof(),
                witnesses_truncated: finding.witnesses_truncated(),
                omitted_witnesses_lower_bound: finding.omitted_witnesses_lower_bound(),
            },
        }
    }
}

struct SarifRelatedLocations<'a>(&'a [RelatedPolicyLocation]);

impl SarifRelatedLocations<'_> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for SarifRelatedLocations<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (index, related) in self.0.iter().enumerate() {
            sequence.serialize_element(&SarifLocation::related(index + 1, related))?;
        }
        sequence.end()
    }
}

struct SarifCodeFlows<'a>(&'a [BoundedWitness]);

impl SarifCodeFlows<'_> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for SarifCodeFlows<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for witness in self.0 {
            sequence.serialize_element(&SarifCodeFlow::from_witness(witness))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct SarifPartialFingerprints {
    #[serde(rename = "bifrostFinding/v1")]
    finding_id: crate::analyzer::policy::PolicyFindingId,
}

#[derive(Serialize)]
struct SarifResultProperties<'a> {
    #[serde(rename = "bifrost.findingId")]
    finding_id: crate::analyzer::policy::PolicyFindingId,
    #[serde(rename = "bifrost.policyHash")]
    policy_hash: PolicySemanticHash,
    #[serde(rename = "bifrost.analysisType")]
    analysis_type: PolicyAnalysisType,
    #[serde(rename = "bifrost.identityStability")]
    identity_stability: FindingIdentityStability,
    #[serde(rename = "bifrost.severity")]
    severity: FindingSeverity,
    #[serde(rename = "bifrost.unrated", skip_serializing_if = "is_false")]
    unrated: bool,
    #[serde(rename = "bifrost.runCompletion")]
    run_completion: &'a PolicyRunCompletion,
    #[serde(rename = "bifrost.findingCompleteness")]
    finding_completeness: &'a FindingCompleteness,
    #[serde(rename = "bifrost.certainty")]
    certainty: &'a FindingCertainty,
    #[serde(rename = "bifrost.classification")]
    classification: &'a crate::analyzer::policy::FindingClassification,
    #[serde(rename = "bifrost.evidence")]
    evidence: &'a PolicyFindingEvidence,
    #[serde(rename = "bifrost.relatedLocationsTruncated")]
    related_locations_truncated: bool,
    #[serde(rename = "bifrost.omittedRelatedLocationsLowerBound")]
    omitted_related_locations_lower_bound: u64,
    #[serde(rename = "bifrost.evidenceRefsTruncated")]
    evidence_refs_truncated: bool,
    #[serde(rename = "bifrost.omittedEvidenceRefsLowerBound")]
    omitted_evidence_refs_lower_bound: u64,
    #[serde(rename = "bifrost.cvss", skip_serializing_if = "Option::is_none")]
    cvss: Option<&'a crate::analyzer::policy::CvssAssessmentSet>,
    #[serde(
        rename = "bifrost.organizationalRisk",
        skip_serializing_if = "Option::is_none"
    )]
    organizational_risk: Option<&'a OrganizationalRiskAssessment>,
    #[serde(rename = "bifrost.proof")]
    proof: &'a ProofMetadata,
    #[serde(rename = "bifrost.witnessesTruncated")]
    witnesses_truncated: bool,
    #[serde(rename = "bifrost.omittedWitnessesLowerBound")]
    omitted_witnesses_lower_bound: u64,
}

#[derive(Serialize)]
struct SarifMessage<'a> {
    text: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    physical_location: Option<SarifPhysicalLocation<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<SarifMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifLocationProperties<'a>>,
}

impl<'a> SarifLocation<'a> {
    fn primary(location: &'a PolicySourceLocation) -> Self {
        Self {
            id: None,
            physical_location: Some(SarifPhysicalLocation::from_policy(location)),
            message: None,
            properties: None,
        }
    }

    fn related(id: usize, related: &'a RelatedPolicyLocation) -> Self {
        let relationship = relationship_label(related);
        Self {
            id: Some(id),
            physical_location: Some(SarifPhysicalLocation::from_policy(related.location())),
            message: Some(SarifMessage { text: relationship }),
            properties: Some(SarifLocationProperties {
                relationship,
                evidence_refs: related.evidence_refs(),
            }),
        }
    }

    fn witness(step: &'a WitnessStep) -> Self {
        Self {
            id: None,
            physical_location: step.location().map(SarifPhysicalLocation::from_policy),
            message: Some(SarifMessage { text: step.label() }),
            properties: None,
        }
    }
}

#[derive(Serialize)]
struct SarifLocationProperties<'a> {
    #[serde(rename = "bifrost.relationship")]
    relationship: &'static str,
    #[serde(rename = "bifrost.evidenceRefs")]
    evidence_refs: &'a [crate::analyzer::policy::EvidenceRef],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation<'a> {
    artifact_location: SarifArtifactLocation<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

impl<'a> SarifPhysicalLocation<'a> {
    fn from_policy(location: &'a PolicySourceLocation) -> Self {
        Self {
            artifact_location: SarifArtifactLocation {
                uri: SarifArtifactUri(location.path()),
                uri_base_id: SOURCE_ROOT_ID,
            },
            region: location.region().map(SarifRegion::from_policy),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation<'a> {
    uri: SarifArtifactUri<'a>,
    uri_base_id: &'static str,
}

struct SarifArtifactUri<'a>(&'a str);

impl Serialize for SarifArtifactUri<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl fmt::Display for SarifArtifactUri<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        note_sarif_artifact_uri_visit();
        write_artifact_uri(formatter, self.0)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
}

impl SarifRegion {
    fn from_policy(region: PolicyDisplayRegion) -> Self {
        Self {
            start_line: region.start_line(),
            start_column: region.start_column(),
            end_line: region.end_line(),
            end_column: region.end_column(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifCodeFlow<'a> {
    message: SarifMessage<'a>,
    thread_flows: [SarifThreadFlow<'a>; 1],
    properties: SarifWitnessProperties<'a>,
}

impl<'a> SarifCodeFlow<'a> {
    fn from_witness(witness: &'a BoundedWitness) -> Self {
        Self {
            message: SarifMessage {
                text: witness.id().as_str(),
            },
            thread_flows: [SarifThreadFlow {
                id: witness.id().as_str(),
                locations: SarifThreadFlowLocations(witness.steps()),
            }],
            properties: SarifWitnessProperties {
                witness_id: witness.id().as_str(),
                truncated: witness.truncated(),
                omitted_steps_lower_bound: witness.omitted_steps_lower_bound(),
            },
        }
    }
}

#[derive(Serialize)]
struct SarifWitnessProperties<'a> {
    #[serde(rename = "bifrost.witnessId")]
    witness_id: &'a str,
    #[serde(rename = "bifrost.truncated")]
    truncated: bool,
    #[serde(rename = "bifrost.omittedStepsLowerBound")]
    omitted_steps_lower_bound: u64,
}

#[derive(Serialize)]
struct SarifThreadFlow<'a> {
    id: &'a str,
    locations: SarifThreadFlowLocations<'a>,
}

struct SarifThreadFlowLocations<'a>(&'a [WitnessStep]);

impl Serialize for SarifThreadFlowLocations<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for step in self.0 {
            sequence.serialize_element(&SarifThreadFlowLocation::from_step(step))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct SarifThreadFlowLocation<'a> {
    location: SarifLocation<'a>,
    properties: SarifWitnessStepProperties<'a>,
}

impl<'a> SarifThreadFlowLocation<'a> {
    fn from_step(step: &'a WitnessStep) -> Self {
        Self {
            location: SarifLocation::witness(step),
            properties: SarifWitnessStepProperties {
                kind: step.kind(),
                evidence_refs: step.evidence_refs(),
            },
        }
    }
}

#[derive(Serialize)]
struct SarifWitnessStepProperties<'a> {
    #[serde(rename = "bifrost.kind")]
    kind: WitnessStepKind,
    #[serde(rename = "bifrost.evidenceRefs")]
    evidence_refs: &'a [crate::analyzer::policy::EvidenceRef],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation<'a> {
    execution_successful: bool,
    tool_execution_notifications: SarifNotifications<'a>,
}

impl<'a> SarifInvocation<'a> {
    fn from_report(report: &'a PolicyReportDocument) -> Self {
        let execution_successful = report.diagnostics().is_empty()
            && !report.diagnostics_truncated()
            && report
                .runs()
                .iter()
                .all(|run| run.completion().is_complete());

        Self {
            execution_successful,
            tool_execution_notifications: SarifNotifications(report),
        }
    }
}

struct SarifNotifications<'a>(&'a PolicyReportDocument);

impl Serialize for SarifNotifications<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let report = self.0;
        let completion_notifications = report
            .runs()
            .iter()
            .filter(|run| !run.completion().is_complete())
            .count();
        let notification_count = report
            .diagnostics()
            .len()
            .checked_add(usize::from(report.diagnostics_truncated()))
            .and_then(|count| count.checked_add(completion_notifications))
            .ok_or_else(|| S::Error::custom("SARIF notification count overflow"))?;
        let mut sequence = serializer.serialize_seq(Some(notification_count))?;
        for diagnostic in report.diagnostics() {
            sequence.serialize_element(&SarifNotification::report_diagnostic(diagnostic))?;
        }
        if report.diagnostics_truncated() {
            sequence.serialize_element(&SarifNotification::truncated_report_diagnostics(report))?;
        }
        for run in report.runs() {
            if let Some(notification) = SarifNotification::policy_completion(run) {
                sequence.serialize_element(&notification)?;
            }
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct SarifNotification<'a> {
    descriptor: SarifDescriptorReference,
    message: SarifMessage<'a>,
    level: SarifNotificationLevel,
    properties: SarifNotificationProperties<'a>,
}

impl<'a> SarifNotification<'a> {
    fn report_diagnostic(diagnostic: &'a PolicyReportDiagnostic) -> Self {
        Self {
            descriptor: SarifDescriptorReference {
                id: "BIFROST_REPORT_DIAGNOSTIC",
            },
            message: SarifMessage {
                text: diagnostic.message(),
            },
            level: notification_level(diagnostic.severity()),
            properties: SarifNotificationProperties {
                policy_id: None,
                policy_hash: None,
                completion: None,
                report_diagnostic: Some(diagnostic),
                diagnostics_truncated: false,
                omitted_diagnostics_lower_bound: 0,
            },
        }
    }

    fn truncated_report_diagnostics(report: &'a PolicyReportDocument) -> Self {
        Self {
            descriptor: SarifDescriptorReference {
                id: "BIFROST_REPORT_DIAGNOSTICS_TRUNCATED",
            },
            message: SarifMessage {
                text: "Bifrost report diagnostics were truncated",
            },
            level: report
                .worst_omitted_diagnostic_severity()
                .map_or(SarifNotificationLevel::Warning, notification_level),
            properties: SarifNotificationProperties {
                policy_id: None,
                policy_hash: None,
                completion: None,
                report_diagnostic: None,
                diagnostics_truncated: true,
                omitted_diagnostics_lower_bound: report.omitted_diagnostics_lower_bound(),
            },
        }
    }

    fn policy_completion(run: &'a PolicyRun) -> Option<Self> {
        let (descriptor_id, text, level) = match run.completion() {
            PolicyRunCompletion::Complete => return None,
            PolicyRunCompletion::Inconclusive { .. } => (
                "BIFROST_POLICY_INCONCLUSIVE",
                "Bifrost policy evaluation was inconclusive",
                SarifNotificationLevel::Warning,
            ),
            PolicyRunCompletion::Unsupported { .. } => (
                "BIFROST_POLICY_UNSUPPORTED",
                "Bifrost policy evaluation was unsupported",
                SarifNotificationLevel::Warning,
            ),
            PolicyRunCompletion::Failed { .. } => (
                "BIFROST_POLICY_FAILED",
                "Bifrost policy evaluation failed",
                SarifNotificationLevel::Error,
            ),
        };
        Some(Self {
            descriptor: SarifDescriptorReference { id: descriptor_id },
            message: SarifMessage { text },
            level,
            properties: SarifNotificationProperties {
                policy_id: Some(run.policy_id().as_str()),
                policy_hash: Some(run.policy_hash()),
                completion: Some(run.completion()),
                report_diagnostic: None,
                diagnostics_truncated: run.diagnostics_truncated(),
                omitted_diagnostics_lower_bound: u64::from(run.diagnostics_truncated()),
            },
        })
    }
}

#[derive(Serialize)]
struct SarifDescriptorReference {
    id: &'static str,
}

#[derive(Serialize)]
struct SarifNotificationProperties<'a> {
    #[serde(rename = "bifrost.policyId", skip_serializing_if = "Option::is_none")]
    policy_id: Option<&'a str>,
    #[serde(rename = "bifrost.policyHash", skip_serializing_if = "Option::is_none")]
    policy_hash: Option<PolicySemanticHash>,
    #[serde(rename = "bifrost.completion", skip_serializing_if = "Option::is_none")]
    completion: Option<&'a PolicyRunCompletion>,
    #[serde(
        rename = "bifrost.reportDiagnostic",
        skip_serializing_if = "Option::is_none"
    )]
    report_diagnostic: Option<&'a PolicyReportDiagnostic>,
    #[serde(rename = "bifrost.diagnosticsTruncated")]
    diagnostics_truncated: bool,
    #[serde(rename = "bifrost.omittedDiagnosticsLowerBound")]
    omitted_diagnostics_lower_bound: u64,
}

#[derive(Serialize)]
struct SarifRunProperties<'a> {
    #[serde(rename = "bifrost.policyReportSchemaVersion")]
    schema_version: u32,
    #[serde(rename = "bifrost.policyRuns")]
    policy_runs: SarifPolicyRuns<'a>,
    #[serde(rename = "bifrost.reportDiagnostics")]
    report_diagnostics: &'a [PolicyReportDiagnostic],
    #[serde(rename = "bifrost.reportDiagnosticsTruncated")]
    diagnostics_truncated: bool,
    #[serde(rename = "bifrost.omittedReportDiagnosticsLowerBound")]
    omitted_diagnostics_lower_bound: u64,
    #[serde(
        rename = "bifrost.worstOmittedReportDiagnosticSeverity",
        skip_serializing_if = "Option::is_none"
    )]
    worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
}

impl<'a> SarifRunProperties<'a> {
    fn from_report(report: &'a PolicyReportDocument) -> Self {
        Self {
            schema_version: report.schema_version(),
            policy_runs: SarifPolicyRuns(report.runs()),
            report_diagnostics: report.diagnostics(),
            diagnostics_truncated: report.diagnostics_truncated(),
            omitted_diagnostics_lower_bound: report.omitted_diagnostics_lower_bound(),
            worst_omitted_diagnostic_severity: report.worst_omitted_diagnostic_severity(),
        }
    }
}

struct SarifPolicyRuns<'a>(&'a [PolicyRun]);

impl Serialize for SarifPolicyRuns<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for run in self.0 {
            sequence.serialize_element(&SarifPolicyRunSummary::from_run(run))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct SarifPolicyRunSummary<'a> {
    policy_id: &'a crate::analyzer::policy::PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    completion: &'a PolicyRunCompletion,
    diagnostics: &'a [PolicyDiagnostic],
    diagnostics_truncated: bool,
    work: &'a PolicyWorkReport,
}

impl<'a> SarifPolicyRunSummary<'a> {
    fn from_run(run: &'a PolicyRun) -> Self {
        Self {
            policy_id: run.policy_id(),
            policy_hash: run.policy_hash(),
            analysis_type: run.analysis_type(),
            completion: run.completion(),
            diagnostics: run.diagnostics(),
            diagnostics_truncated: run.diagnostics_truncated(),
            work: run.work(),
        }
    }
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum SarifLevel {
    None,
    Note,
    Warning,
    Error,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum SarifNotificationLevel {
    Note,
    Warning,
    Error,
}

fn rule_default_level(severity: &PolicySeveritySpec) -> SarifLevel {
    match severity {
        PolicySeveritySpec::Fixed { level } => policy_level(*level),
        PolicySeveritySpec::Unrated => SarifLevel::None,
        PolicySeveritySpec::Cvss { when_unscored } => finding_level(*when_unscored),
    }
}

fn policy_level(level: PolicyLevel) -> SarifLevel {
    match level {
        PolicyLevel::Note => SarifLevel::Note,
        PolicyLevel::Warning => SarifLevel::Warning,
        PolicyLevel::Error => SarifLevel::Error,
    }
}

fn finding_level(severity: FindingSeverity) -> SarifLevel {
    match severity {
        FindingSeverity::Unrated => SarifLevel::None,
        FindingSeverity::Note => SarifLevel::Note,
        FindingSeverity::Warning => SarifLevel::Warning,
        FindingSeverity::Error => SarifLevel::Error,
    }
}

fn notification_level(severity: PolicyDiagnosticSeverity) -> SarifNotificationLevel {
    match severity {
        PolicyDiagnosticSeverity::Note => SarifNotificationLevel::Note,
        PolicyDiagnosticSeverity::Warning => SarifNotificationLevel::Warning,
        PolicyDiagnosticSeverity::Error => SarifNotificationLevel::Error,
    }
}

fn relationship_label(related: &RelatedPolicyLocation) -> &'static str {
    use crate::analyzer::policy::PolicyLocationRelationship;

    match related.relationship() {
        PolicyLocationRelationship::Source => "source",
        PolicyLocationRelationship::Sink => "sink",
        PolicyLocationRelationship::Origin => "origin",
        PolicyLocationRelationship::Evidence => "evidence",
        PolicyLocationRelationship::WitnessStep => "witness step",
        PolicyLocationRelationship::Declaration => "declaration",
        PolicyLocationRelationship::CallTarget => "call target",
    }
}

fn write_artifact_uri<W: fmt::Write + ?Sized>(output: &mut W, path: &str) -> fmt::Result {
    for byte in path.bytes() {
        if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
        {
            fmt::Write::write_char(output, char::from(byte))?;
        } else {
            write!(output, "%{byte:02X}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn encode_artifact_uri(path: &str) -> String {
    let mut encoded = String::new();
    write_artifact_uri(&mut encoded, path).expect("writing to a string cannot fail");
    encoded
}

#[cfg(test)]
thread_local! {
    static SARIF_RESULT_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SARIF_ARTIFACT_URI_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_sarif_result_visit() {
    SARIF_RESULT_VISITS.with(|visits| visits.set(visits.get().saturating_add(1)));
}

#[cfg(not(test))]
fn note_sarif_result_visit() {}

#[cfg(test)]
fn note_sarif_artifact_uri_visit() {
    SARIF_ARTIFACT_URI_VISITS.with(|visits| visits.set(visits.get().saturating_add(1)));
}

#[cfg(not(test))]
fn note_sarif_artifact_uri_visit() {}

#[cfg(test)]
fn reset_sarif_stream_visits() {
    SARIF_RESULT_VISITS.with(|visits| visits.set(0));
    SARIF_ARTIFACT_URI_VISITS.with(|visits| visits.set(0));
}

#[cfg(test)]
fn sarif_stream_visits() -> (usize, usize) {
    (
        SARIF_RESULT_VISITS.with(std::cell::Cell::get),
        SARIF_ARTIFACT_URI_VISITS.with(std::cell::Cell::get),
    )
}

fn normalize_absolute_uri(uri: &str) -> Option<String> {
    let syntax_violation = std::cell::Cell::new(false);
    let record_violation = |_| syntax_violation.set(true);
    let parsed = url::Url::options()
        .syntax_violation_callback(Some(&record_violation))
        .parse(uri);
    parsed
        .ok()
        .filter(|parsed| !parsed.scheme().is_empty() && !syntax_violation.get())
        .map(|parsed| parsed.to_string())
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::analyzer::semantic::WorkspaceRelativePath;
    use crate::policy::{PolicyFailOn, evaluate_policy_files};

    #[test]
    fn artifact_uri_preserves_only_segment_separators_and_unreserved_bytes() {
        assert_eq!(
            encode_artifact_uri("src/a b#%/café\n\u{202E}.py"),
            "src/a%20b%23%25/caf%C3%A9%0A%E2%80%AE.py"
        );
        assert!(!encode_artifact_uri("a/b").contains("%2F"));
    }

    #[test]
    fn zero_byte_bound_stops_before_results_or_artifact_uris_are_visited() {
        let fixture_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy-cli/project");
        let outcome = evaluate_policy_files(
            &fixture_root,
            &[PathBuf::from("policies/dynamic-eval.rqlp")],
            false,
            PolicyFailOn::Never,
        )
        .expect("fixture policy evaluation");
        assert_eq!(outcome.report().runs()[0].findings().len(), 1);

        reset_sarif_stream_visits();
        let mut output = Vec::new();
        assert!(matches!(
            write_policy_sarif(
                outcome.report(),
                &SarifToolIdentity::default(),
                &mut output,
                0,
            ),
            Err(PolicyRenderError::SerializedReportLimit {
                max_serialized_bytes: 0
            })
        ));
        assert!(output.is_empty());
        assert_eq!(sarif_stream_visits(), (0, 0));

        reset_sarif_stream_visits();
        write_policy_sarif(
            outcome.report(),
            &SarifToolIdentity::default(),
            Vec::new(),
            usize::MAX,
        )
        .expect("unbounded fixture SARIF");
        assert_eq!(sarif_stream_visits(), (1, 1));
    }

    #[test]
    fn default_tool_identity_is_stable_and_complete() {
        let tool = SarifToolIdentity::default();
        assert_eq!(tool.name(), "Bifrost");
        assert_eq!(tool.version(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(tool.information_uri(), Some(env!("CARGO_PKG_HOMEPAGE")));
        tool.validate().unwrap();
    }

    #[test]
    fn tool_identity_rejects_empty_fields_and_non_absolute_uris() {
        assert!(SarifToolIdentity::new("").validate().is_err());
        assert!(
            SarifToolIdentity::new("Bifrost")
                .with_version("")
                .validate()
                .is_err()
        );
        for uri in [
            "relative/path",
            "https://",
            "https://exa mple.test/tool",
            "https://example.test/%1",
        ] {
            assert!(
                SarifToolIdentity::new("Bifrost")
                    .with_information_uri(uri)
                    .validate()
                    .is_err(),
                "unexpected valid URI: {uri}"
            );
        }
        for uri in ["https://example.test/tool?v=1#release", "urn:brokk:bifrost"] {
            SarifToolIdentity::new("Bifrost")
                .with_information_uri(uri)
                .validate()
                .unwrap();
        }
        assert_eq!(
            normalize_absolute_uri("HTTPS://Example.Test/tool"),
            Some("https://example.test/tool".to_string())
        );
    }

    #[test]
    fn truncated_policy_diagnostics_report_a_nonzero_omission_lower_bound() {
        let fixture_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy-cli/project");
        let outcome = evaluate_policy_files(
            &fixture_root,
            &[PathBuf::from("policies/resource-lifecycle.rqlp")],
            false,
            PolicyFailOn::Never,
        )
        .expect("fixture policy evaluation");
        let mut run = outcome.report().runs()[0].clone();
        run.replace_diagnostics(run.diagnostics().to_vec(), true);

        let notification = SarifNotification::policy_completion(&run)
            .expect("the unsupported policy produces a completion notification");
        let value = serde_json::to_value(notification).expect("serialize notification");
        assert_eq!(value["properties"]["bifrost.diagnosticsTruncated"], true);
        assert_eq!(
            value["properties"]["bifrost.omittedDiagnosticsLowerBound"],
            1
        );
    }

    #[test]
    fn related_locations_and_witness_steps_keep_their_semantic_order() {
        let source_location = PolicySourceLocation::span(
            WorkspaceRelativePath::new("src/source file.ts").unwrap(),
            crate::analyzer::policy::PolicyByteSpan::new(0, 1).unwrap(),
            PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
        );
        let sink_location = PolicySourceLocation::span(
            WorkspaceRelativePath::new("src/sink.ts").unwrap(),
            crate::analyzer::policy::PolicyByteSpan::new(2, 3).unwrap(),
            PolicyDisplayRegion::new(2, 3, 2, 4).unwrap(),
        );
        let related = RelatedPolicyLocation::try_new(
            crate::analyzer::policy::PolicyLocationRelationship::Source,
            source_location.clone(),
            vec![crate::analyzer::policy::EvidenceRef::try_new("test", "source").unwrap()],
        )
        .unwrap();
        let related_wire = serde_json::to_value(SarifLocation::related(1, &related)).unwrap();
        assert_eq!(related_wire["id"], 1);
        assert_eq!(
            related_wire["physicalLocation"]["artifactLocation"]["uri"],
            "src/source%20file.ts"
        );
        assert_eq!(related_wire["properties"]["bifrost.relationship"], "source");

        let witness = BoundedWitness::try_new(
            crate::analyzer::policy::WitnessId::try_new("test", "flow").unwrap(),
            vec![
                WitnessStep::try_new(
                    WitnessStepKind::Source,
                    Some(source_location),
                    "source step",
                    Vec::new(),
                )
                .unwrap(),
                WitnessStep::try_new(
                    WitnessStepKind::Violation,
                    Some(sink_location),
                    "sink step",
                    Vec::new(),
                )
                .unwrap(),
            ],
            false,
            0,
        )
        .unwrap();
        let code_flow = serde_json::to_value(SarifCodeFlow::from_witness(&witness)).unwrap();
        let locations = code_flow["threadFlows"][0]["locations"].as_array().unwrap();
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0]["location"]["message"]["text"], "source step");
        assert_eq!(locations[1]["location"]["message"]["text"], "sink step");
        assert_eq!(locations[0]["properties"]["bifrost.kind"], "source");
        assert_eq!(locations[1]["properties"]["bifrost.kind"], "violation");
    }
}
