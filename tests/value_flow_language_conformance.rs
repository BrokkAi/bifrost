mod common;
#[path = "common/value_flow_conformance.rs"]
mod value_flow_conformance;

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::dataflow::{PathQuality, SemanticInputStatus};
use brokk_bifrost::analyzer::semantic::{
    EvidenceCompleteness, IcfgEdgeKind, ProcedureKind, ProofStatus,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowMayStatus, ValueFlowMustStatus, ValueFlowPortKey,
};

use value_flow_conformance::{
    CallArgumentSink, CallSelector, CarrierMilestone, ExpectedMeeting, ExpectedSinkOutcome,
    ExpectedWitness, InlineSourceFile, InterproceduralMilestone, ParameterSource,
    ProcedureSelector, ValueFlowConformanceCase, assert_value_flow_conformance,
};

const JAVA_SOURCE: &str = r#"
final class ExactFlowFixture {
  static String relay(String value) {
    String relayed = value;
    return relayed;
  }

  static void sink(String flowed, String clean) {}

  static void run(String input) {
    String copy = relay(input);
    String clean = "clean";
    sink(copy, clean);
  }
}
"#;

const JAVA_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/ExactFlowFixture.java",
    source: JAVA_SOURCE,
}];

const TYPESCRIPT_SOURCE: &str = r#"
function relay(value: string): string {
  const relayed = value;
  return relayed;
}

function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  const copy = relay(input);
  const clean = "clean";
  sink(copy, clean);
}
"#;

const TYPESCRIPT_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/exact_flow.ts",
    source: TYPESCRIPT_SOURCE,
}];

const JAVA_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/ExactFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/ExactFlowFixture.java",
        name: "relay",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/ExactFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/exact_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/exact_flow.ts",
        name: "relay",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/exact_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const CALLS: &[CallSelector<'_>] = &[
    CallSelector {
        alias: "relay_call",
        caller: "run",
        callee: "relay",
        occurrence: 0,
    },
    CallSelector {
        alias: "sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 0,
    },
];

const JAVA_SINKS: &[CallArgumentSink<'_>] = &[
    CallArgumentSink {
        alias: "flowed",
        call: "sink_call",
        argument: 0,
        outcome: ExpectedSinkOutcome::Reached,
    },
    CallArgumentSink {
        alias: "clean",
        call: "sink_call",
        argument: 1,
        outcome: ExpectedSinkOutcome::NotReached,
    },
];

const TYPESCRIPT_SINKS: &[CallArgumentSink<'_>] = &[
    CallArgumentSink {
        alias: "flowed",
        call: "sink_call",
        argument: 0,
        outcome: ExpectedSinkOutcome::Reached,
    },
    CallArgumentSink {
        alias: "clean",
        call: "sink_call",
        argument: 1,
        outcome: ExpectedSinkOutcome::Inconclusive,
    },
];

fn expected_carriers(path: &str) -> Vec<CarrierMilestone> {
    vec![
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
        },
        CarrierMilestone::CallArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "relay".into(),
            call: "relay(input)".into(),
            ordinal: 0,
        },
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "relay".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
        },
        CarrierMilestone::Value {
            path: path.into(),
            procedure: "relay".into(),
            role: "local".into(),
            ordinal: None,
            snippet: "relayed".into(),
        },
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "relay".into(),
            kind: ValueFlowPortKey::NormalReturn,
        },
        CarrierMilestone::CallResult {
            path: path.into(),
            caller: "run".into(),
            callee: "relay".into(),
            call: "relay(input)".into(),
            result: ValueFlowPortKey::NormalReturn,
        },
        CarrierMilestone::Value {
            path: path.into(),
            procedure: "run".into(),
            role: "local".into(),
            ordinal: None,
            snippet: "copy".into(),
        },
        CarrierMilestone::SinkArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: "sink(copy, clean)".into(),
            ordinal: 0,
        },
    ]
}

const EXPECTED_INTERPROCEDURAL: &[InterproceduralMilestone<'_>] = &[
    InterproceduralMilestone {
        kind: IcfgEdgeKind::Call,
        source_procedure: "run",
        target_procedure: "relay",
        origin_call: "relay_call",
    },
    InterproceduralMilestone {
        kind: IcfgEdgeKind::NormalReturn,
        source_procedure: "relay",
        target_procedure: "run",
        origin_call: "relay_call",
    },
];

const EXPECTED_PATH_QUALITIES: &[PathQuality] = &[PathQuality::PROVEN_COMPLETE];
const EXPECTED_STEP_PROOF: ProofStatus = ProofStatus::Proven;
const EXPECTED_STEP_COMPLETENESS: EvidenceCompleteness = EvidenceCompleteness::Complete;

fn expected_meetings<'case>(
    carriers: &'case [CarrierMilestone],
    meeting_count: usize,
) -> [ExpectedMeeting<'case>; 1] {
    [ExpectedMeeting {
        sink: "flowed",
        meeting_count,
        may_status: ValueFlowMayStatus::Proven,
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            step_proof: &EXPECTED_STEP_PROOF,
            step_completeness: &EXPECTED_STEP_COMPLETENESS,
            carriers,
            interprocedural: EXPECTED_INTERPROCEDURAL,
        },
    }]
}

#[test]
fn java_exact_helper_flow() {
    let expected_carriers = expected_carriers("src/ExactFlowFixture.java");
    let expected_meetings = expected_meetings(&expected_carriers, 1);
    assert_value_flow_conformance(&ValueFlowConformanceCase {
        name: "java",
        language: Language::Java,
        files: JAVA_FILES,
        procedures: JAVA_PROCEDURES,
        root: "run",
        calls: CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks: JAVA_SINKS,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete: true,
        expected_meetings: &expected_meetings,
    });
}

#[test]
fn typescript_exact_helper_flow() {
    let expected_carriers = expected_carriers("src/exact_flow.ts");
    let expected_meetings = expected_meetings(&expected_carriers, 6);
    assert_value_flow_conformance(&ValueFlowConformanceCase {
        name: "typescript",
        language: Language::TypeScript,
        files: TYPESCRIPT_FILES,
        procedures: TYPESCRIPT_PROCEDURES,
        root: "run",
        calls: CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks: TYPESCRIPT_SINKS,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_meetings: &expected_meetings,
    });
}
