//! Shared source-backed value-flow scenario descriptions.
//!
//! Each scenario is materialized through a closure so its expected witness can
//! borrow locally constructed carrier milestones without leaking test-run
//! state. Direct and public-query executors receive the exact same case value.

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::dataflow::{PathQuality, SemanticInputStatus};
use brokk_bifrost::analyzer::semantic::{IcfgEdgeKind, ProcedureKind};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowMayStatus, ValueFlowMustStatus, ValueFlowPortKey,
};

use crate::value_flow_conformance::{
    CallArgumentSink, CallSelector, CarrierMilestone, ExpectedMeeting, ExpectedSinkOutcome,
    ExpectedWitness, InlineSourceFile, InterproceduralMilestone, ParameterSource,
    ProcedureSelector, ValueFlowConformanceCase,
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

const JAVA_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/ExactFlowFixture.java",
    source: JAVA_SOURCE,
}];

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

pub fn with_java_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_exact_helper(
        "java",
        Language::Java,
        JAVA_FILES,
        JAVA_PROCEDURES,
        JAVA_SINKS,
        "src/ExactFlowFixture.java",
        1,
        1,
        SemanticInputStatus::Unknown,
        false,
        true,
        execute,
    )
}

pub fn with_typescript_exact_helper<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_exact_helper(
        "typescript",
        Language::TypeScript,
        TYPESCRIPT_FILES,
        TYPESCRIPT_PROCEDURES,
        TYPESCRIPT_SINKS,
        "src/exact_flow.ts",
        6,
        4,
        SemanticInputStatus::Unknown,
        false,
        false,
        execute,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_exact_helper<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    sinks: &[CallArgumentSink<'_>],
    path: &str,
    meeting_count: usize,
    public_endpoint_count: usize,
    expected_discovery_status: SemanticInputStatus,
    expected_discovery_complete: bool,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let carriers = vec![
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
    ];
    let meetings = [ExpectedMeeting {
        sink: "flowed",
        meeting_count,
        public_endpoint_count,
        may_status: ValueFlowMayStatus::Proven,
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            carriers: &carriers,
            interprocedural: EXPECTED_INTERPROCEDURAL,
        },
    }];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks,
        expected_discovery_status,
        expected_discovery_complete,
        expected_result_complete,
        expected_meetings: &meetings,
    })
}
