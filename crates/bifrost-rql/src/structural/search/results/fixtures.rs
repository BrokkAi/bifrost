use std::collections::HashSet;

use serde_json::Value;

use super::*;

impl Default for CodeQueryCandidateRef {
    fn default() -> Self {
        Self::ExternalRoute {
            name: String::new(),
        }
    }
}

impl Default for CodeQueryTypestateFindingKind {
    fn default() -> Self {
        Self::TerminalExpectation {
            expectation: String::new(),
            actual_states: Vec::new(),
        }
    }
}

impl Default for CodeQueryFlowCarrierSymbol {
    fn default() -> Self {
        Self::Value {
            id: String::new(),
            site: Default::default(),
            role: String::new(),
            ordinal: None,
        }
    }
}

/// Serialize one default-valued instance of every canonical result variant.
///
/// The schema comparison makes a newly added variant fail this fixture path
/// until its real Rust value is included. Python then decodes these serde bytes,
/// covering tags, omission/default behavior, diagnostics, and renamed fields.
#[must_use]
pub fn code_query_result_fixtures_json() -> Value {
    let values = vec![
        CodeQueryResultValue::StructuralMatch {
            value: Default::default(),
        },
        CodeQueryResultValue::Declaration {
            value: Default::default(),
        },
        CodeQueryResultValue::Procedure {
            value: Default::default(),
        },
        CodeQueryResultValue::ProgramPoint {
            value: Default::default(),
        },
        CodeQueryResultValue::ControlEdge {
            value: Default::default(),
        },
        CodeQueryResultValue::TypestateFinding {
            value: Default::default(),
        },
        CodeQueryResultValue::ConcurrentAccessConflict {
            value: Default::default(),
        },
        CodeQueryResultValue::TypestateWitness {
            value: Default::default(),
        },
        CodeQueryResultValue::FlowEndpoint {
            value: Default::default(),
        },
        CodeQueryResultValue::FlowWitness {
            value: Default::default(),
        },
        CodeQueryResultValue::ClassSetRow {
            value: Default::default(),
        },
        CodeQueryResultValue::AbsentMemberFinding {
            value: Default::default(),
        },
        CodeQueryResultValue::AbsentMemberWitness {
            value: Default::default(),
        },
        CodeQueryResultValue::TaintFinding {
            value: Default::default(),
        },
        CodeQueryResultValue::File {
            value: Default::default(),
        },
        CodeQueryResultValue::ConfigurationFact {
            value: Default::default(),
        },
        CodeQueryResultValue::ReferenceSite {
            value: Default::default(),
        },
        CodeQueryResultValue::CallSite {
            value: Default::default(),
        },
        CodeQueryResultValue::ExpressionSite {
            value: Default::default(),
        },
        CodeQueryResultValue::JsxAttributeValue {
            value: Default::default(),
        },
        CodeQueryResultValue::ReceiverAnalysis {
            value: Default::default(),
        },
        CodeQueryResultValue::MemberTargetAnalysis {
            value: Default::default(),
        },
        CodeQueryResultValue::ReceiverOutcome {
            value: Default::default(),
        },
        CodeQueryResultValue::ReceiverEvidence {
            value: Default::default(),
        },
        CodeQueryResultValue::FieldWriteValue {
            value: Default::default(),
        },
        CodeQueryResultValue::RuntimeKeyedReadValue {
            value: Default::default(),
        },
        CodeQueryResultValue::CallShape {
            value: Default::default(),
        },
        CodeQueryResultValue::CallResult {
            value: Default::default(),
        },
        CodeQueryResultValue::CallArgumentGroup {
            value: Default::default(),
        },
        CodeQueryResultValue::CallArgument {
            value: Default::default(),
        },
        CodeQueryResultValue::CallBinding {
            value: Default::default(),
        },
        CodeQueryResultValue::CallEffect {
            value: Default::default(),
        },
        CodeQueryResultValue::CallResultContract {
            value: Default::default(),
        },
        CodeQueryResultValue::CallResultObligation {
            value: Default::default(),
        },
        CodeQueryResultValue::ResultContractUse {
            value: Default::default(),
        },
        CodeQueryResultValue::ResultContractFailureUse {
            value: Default::default(),
        },
        CodeQueryResultValue::NilnessOperation {
            value: Default::default(),
        },
        CodeQueryResultValue::SwitchCoverage {
            value: Default::default(),
        },
        CodeQueryResultValue::AssignmentRelation {
            value: Default::default(),
        },
        CodeQueryResultValue::DetachedTaskTransfer {
            value: Default::default(),
        },
        CodeQueryResultValue::ProcedureEffect {
            value: Default::default(),
        },
        CodeQueryResultValue::CallableSignature {
            value: Default::default(),
        },
        CodeQueryResultValue::SignatureParameter {
            value: Default::default(),
        },
        CodeQueryResultValue::DecoratedParameter {
            value: Default::default(),
        },
        CodeQueryResultValue::CallableApplicability {
            value: Default::default(),
        },
        CodeQueryResultValue::OverloadSelection {
            value: Default::default(),
        },
        CodeQueryResultValue::MemberSelection {
            value: Default::default(),
        },
        CodeQueryResultValue::DispatchOutcome {
            value: Default::default(),
        },
        CodeQueryResultValue::DispatchTarget {
            value: Default::default(),
        },
        CodeQueryResultValue::MemberFamily {
            value: Default::default(),
        },
        CodeQueryResultValue::MemberFamilyEdge {
            value: Default::default(),
        },
        CodeQueryResultValue::Occurrence {
            value: Default::default(),
        },
        CodeQueryResultValue::LexicalScope {
            value: Default::default(),
        },
        CodeQueryResultValue::Binding {
            value: Default::default(),
        },
        CodeQueryResultValue::ResolutionCandidate {
            value: Default::default(),
        },
        CodeQueryResultValue::CandidateHop {
            value: Default::default(),
        },
        CodeQueryResultValue::GenerationSite {
            value: Default::default(),
        },
        CodeQueryResultValue::Export {
            value: Default::default(),
        },
        CodeQueryResultValue::DeclarationState {
            value: Default::default(),
        },
        CodeQueryResultValue::ReferenceEdge {
            value: Default::default(),
        },
        CodeQueryResultValue::StateEvent {
            value: Default::default(),
        },
        CodeQueryResultValue::FlowRelation {
            value: Default::default(),
        },
        CodeQueryResultValue::ControlRelation {
            value: Default::default(),
        },
        CodeQueryResultValue::BranchRelation {
            value: Default::default(),
        },
        CodeQueryResultValue::LoopRelation {
            value: Default::default(),
        },
        CodeQueryResultValue::FailureHandlerState {
            value: Default::default(),
        },
        CodeQueryResultValue::StatementReachability {
            value: Default::default(),
        },
        CodeQueryResultValue::Guard {
            value: Default::default(),
        },
        CodeQueryResultValue::RewritePath {
            value: Default::default(),
        },
        CodeQueryResultValue::QualifiedPath {
            value: Default::default(),
        },
        CodeQueryResultValue::PathSegment {
            value: Default::default(),
        },
        CodeQueryResultValue::SourceSet {
            value: Default::default(),
        },
        CodeQueryResultValue::BuildTarget {
            value: Default::default(),
        },
        CodeQueryResultValue::TopologyEdge {
            value: Default::default(),
        },
    ];
    let result = CodeQueryResult {
        results: values
            .into_iter()
            .map(|value| CodeQueryResultItem {
                value,
                provenance: Vec::new(),
                provenance_truncated: false,
                row_projection: Vec::new(),
            })
            .collect(),
        truncated: false,
        session_subset: None,
        diagnostics: vec![CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::InvalidPlan,
            impact: CodeQueryDiagnosticImpact::Invalid,
            branch: Vec::new(),
            language: "workspace",
            message: "fixture diagnostic".to_owned(),
            exhausted_roots: Vec::new(),
        }],
    };
    let serialized =
        serde_json::to_value(result).expect("the canonical Rust result fixtures are serializable");

    let actual = serialized["results"]
        .as_array()
        .expect("serialized fixtures retain their result rows")
        .iter()
        .map(|row| {
            row["result_type"]
                .as_str()
                .expect("serialized fixture row retains its result_type")
        })
        .collect::<HashSet<_>>();
    let schema = code_query_result_json_schema();
    let expected = schema["$defs"]["CodeQueryResultItem"]["oneOf"]
        .as_array()
        .expect("the result item schema is a tagged union")
        .iter()
        .map(|variant| {
            variant["properties"]["result_type"]["const"]
                .as_str()
                .expect("a result schema variant has a string tag")
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        actual, expected,
        "fixture and schema result variants differ"
    );
    serialized
}
