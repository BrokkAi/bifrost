mod common;

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::semantic::{IcfgEdgeKind, ProcedureKind};
use brokk_bifrost::analyzer::value_flow::ValueFlowPortKey;

use common::value_flow_conformance::{
    AbsentSinkExpectation, CallArgumentSink, CallSelector, CarrierMilestone, InlineSourceFile,
    InterproceduralMilestone, ParameterSource, ProcedureSelector, ValueFlowConformanceCase,
    assert_value_flow_conformance,
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

const SINKS: &[CallArgumentSink<'_>] = &[
    CallArgumentSink {
        alias: "flowed",
        call: "sink_call",
        argument: 0,
        reached: true,
        absent_outcome: None,
    },
    CallArgumentSink {
        alias: "clean",
        call: "sink_call",
        argument: 1,
        reached: false,
        absent_outcome: Some(AbsentSinkExpectation::Inconclusive),
    },
];

const EXPECTED_CARRIERS: &[CarrierMilestone<'_>] = &[
    CarrierMilestone::Port {
        procedure: "run",
        kind: ValueFlowPortKey::Parameter { ordinal: 0 },
    },
    CarrierMilestone::CallArgument {
        caller: "run",
        callee: "relay",
        ordinal: 0,
    },
    CarrierMilestone::Port {
        procedure: "relay",
        kind: ValueFlowPortKey::Parameter { ordinal: 0 },
    },
    CarrierMilestone::Value {
        procedure: "relay",
        role: "local",
        ordinal: None,
    },
    CarrierMilestone::Port {
        procedure: "relay",
        kind: ValueFlowPortKey::NormalReturn,
    },
    CarrierMilestone::CallResult {
        caller: "run",
        callee: "relay",
        result: ValueFlowPortKey::NormalReturn,
    },
    CarrierMilestone::Value {
        procedure: "run",
        role: "local",
        ordinal: None,
    },
    CarrierMilestone::SinkArgument {
        caller: "run",
        callee: "sink",
        ordinal: 0,
    },
];

const EXPECTED_INTERPROCEDURAL: &[InterproceduralMilestone<'_>] = &[
    InterproceduralMilestone {
        kind: IcfgEdgeKind::Call,
        source_procedure: "run",
        target_procedure: "relay",
        origin_procedure: "run",
    },
    InterproceduralMilestone {
        kind: IcfgEdgeKind::NormalReturn,
        source_procedure: "relay",
        target_procedure: "run",
        origin_procedure: "run",
    },
];

#[test]
fn java_exact_helper_flow() {
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
        sinks: SINKS,
        expected_complete: false,
        expected_carriers: EXPECTED_CARRIERS,
        expected_interprocedural: EXPECTED_INTERPROCEDURAL,
    });
}

#[test]
fn typescript_exact_helper_flow() {
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
        sinks: SINKS,
        expected_complete: false,
        expected_carriers: EXPECTED_CARRIERS,
        expected_interprocedural: EXPECTED_INTERPROCEDURAL,
    });
}
