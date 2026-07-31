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

const JAVA_BRANCH_SOURCE: &str = r#"
final class BranchFlowFixture {
  static void sink(String flowed, String clean) {}

  static void run(String input, boolean choose) {
    String copy = "clean";
    if (choose) {
      copy = input;
    }
    String clean = "clean";
    sink(copy, clean);
  }
}
"#;

const TYPESCRIPT_BRANCH_SOURCE: &str = r#"
function sink(flowed: string, clean: string): void {}

function run(input: string, choose: boolean): void {
  let copy = "clean";
  if (choose) {
    copy = input;
  }
  const clean = "clean";
  sink(copy, clean);
}
"#;

const JAVA_LOOP_SOURCE: &str = r#"
final class LoopFlowFixture {
  static void sink(String flowed, String clean) {}

  static void run(String input, boolean repeat) {
    String copy = "clean";
    while (repeat) {
      copy = input;
      repeat = false;
    }
    String clean = "clean";
    sink(copy, clean);
  }
}
"#;

const TYPESCRIPT_LOOP_SOURCE: &str = r#"
function sink(flowed: string, clean: string): void {}

function run(input: string, repeat: boolean): void {
  let copy = "clean";
  while (repeat) {
    copy = input;
    repeat = false;
  }
  const clean = "clean";
  sink(copy, clean);
}
"#;

const JAVA_EARLY_RETURN_SOURCE: &str = r#"
final class EarlyReturnFlowFixture {
  static void sink(String flowed, String clean) {}

  static void run(String input, boolean stop) {
    if (stop) {
      return;
    }
    String copy = input;
    String clean = "clean";
    sink(copy, clean);
    return;
    sink(input, clean);
  }
}
"#;

const TYPESCRIPT_EARLY_RETURN_SOURCE: &str = r#"
function sink(flowed: string, clean: string): void {}

function run(input: string, stop: boolean): void {
  if (stop) {
    return;
  }
  const copy = input;
  const clean = "clean";
  sink(copy, clean);
  return;
  sink(input, clean);
}
"#;

const JAVA_TWO_CALL_SOURCE: &str = r#"
final class TwoCallFlowFixture {
  static String relay(String value) {
    String relayed = value;
    return relayed;
  }

  static void sink(String flowed, String clean) {}

  static void run(String input) {
    String first = relay(input);
    String second = relay(first);
    String clean = "clean";
    sink(second, clean);
  }
}
"#;

const TYPESCRIPT_TWO_CALL_SOURCE: &str = r#"
function relay(value: string): string {
  const relayed = value;
  return relayed;
}

function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  const first = relay(input);
  const second = relay(first);
  const clean = "clean";
  sink(second, clean);
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

const JAVA_BRANCH_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/BranchFlowFixture.java",
    source: JAVA_BRANCH_SOURCE,
}];

const TYPESCRIPT_BRANCH_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/branch_flow.ts",
    source: TYPESCRIPT_BRANCH_SOURCE,
}];

const JAVA_LOOP_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/LoopFlowFixture.java",
    source: JAVA_LOOP_SOURCE,
}];

const TYPESCRIPT_LOOP_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/loop_flow.ts",
    source: TYPESCRIPT_LOOP_SOURCE,
}];

const JAVA_EARLY_RETURN_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/EarlyReturnFlowFixture.java",
    source: JAVA_EARLY_RETURN_SOURCE,
}];

const TYPESCRIPT_EARLY_RETURN_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/early_return_flow.ts",
    source: TYPESCRIPT_EARLY_RETURN_SOURCE,
}];

const JAVA_TWO_CALL_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/TwoCallFlowFixture.java",
    source: JAVA_TWO_CALL_SOURCE,
}];

const TYPESCRIPT_TWO_CALL_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/two_call_flow.ts",
    source: TYPESCRIPT_TWO_CALL_SOURCE,
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

const JAVA_BRANCH_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/BranchFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/BranchFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_BRANCH_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/branch_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/branch_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_LOOP_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/LoopFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/LoopFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_LOOP_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/loop_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/loop_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_EARLY_RETURN_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/EarlyReturnFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/EarlyReturnFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_EARLY_RETURN_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/early_return_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/early_return_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_TWO_CALL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/TwoCallFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/TwoCallFlowFixture.java",
        name: "relay",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/TwoCallFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_TWO_CALL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/two_call_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/two_call_flow.ts",
        name: "relay",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/two_call_flow.ts",
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

const BRANCH_CALLS: &[CallSelector<'_>] = &[CallSelector {
    alias: "sink_call",
    caller: "run",
    callee: "sink",
    occurrence: 0,
}];

const EARLY_RETURN_CALLS: &[CallSelector<'_>] = &[
    CallSelector {
        alias: "sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 0,
    },
    CallSelector {
        alias: "unreachable_sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 1,
    },
];

const TWO_CALLS: &[CallSelector<'_>] = &[
    CallSelector {
        alias: "relay_first",
        caller: "run",
        callee: "relay",
        occurrence: 0,
    },
    CallSelector {
        alias: "relay_second",
        caller: "run",
        callee: "relay",
        occurrence: 1,
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

const JAVA_BRANCH_SINKS: &[CallArgumentSink<'_>] = &[
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

const TYPESCRIPT_BRANCH_SINKS: &[CallArgumentSink<'_>] = &[
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

const TWO_CALL_INTERPROCEDURAL: &[InterproceduralMilestone<'_>] = &[
    InterproceduralMilestone {
        kind: IcfgEdgeKind::Call,
        source_procedure: "run",
        target_procedure: "relay",
        origin_call: "relay_first",
    },
    InterproceduralMilestone {
        kind: IcfgEdgeKind::NormalReturn,
        source_procedure: "relay",
        target_procedure: "run",
        origin_call: "relay_first",
    },
    InterproceduralMilestone {
        kind: IcfgEdgeKind::Call,
        source_procedure: "run",
        target_procedure: "relay",
        origin_call: "relay_second",
    },
    InterproceduralMilestone {
        kind: IcfgEdgeKind::NormalReturn,
        source_procedure: "relay",
        target_procedure: "run",
        origin_call: "relay_second",
    },
];

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

pub fn with_java_branch_merge<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_branch_merge(
        "java-branch-merge",
        Language::Java,
        JAVA_BRANCH_FILES,
        JAVA_BRANCH_PROCEDURES,
        JAVA_BRANCH_SINKS,
        "src/BranchFlowFixture.java",
        1,
        1,
        true,
        execute,
    )
}

pub fn with_typescript_branch_merge<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_branch_merge(
        "typescript-branch-merge",
        Language::TypeScript,
        TYPESCRIPT_BRANCH_FILES,
        TYPESCRIPT_BRANCH_PROCEDURES,
        TYPESCRIPT_BRANCH_SINKS,
        "src/branch_flow.ts",
        3,
        3,
        false,
        execute,
    )
}

pub fn with_java_loop_exit<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_branch_merge(
        "java-loop-exit",
        Language::Java,
        JAVA_LOOP_FILES,
        JAVA_LOOP_PROCEDURES,
        JAVA_BRANCH_SINKS,
        "src/LoopFlowFixture.java",
        1,
        1,
        true,
        execute,
    )
}

pub fn with_typescript_loop_exit<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_branch_merge(
        "typescript-loop-exit",
        Language::TypeScript,
        TYPESCRIPT_LOOP_FILES,
        TYPESCRIPT_LOOP_PROCEDURES,
        TYPESCRIPT_BRANCH_SINKS,
        "src/loop_flow.ts",
        3,
        3,
        false,
        execute,
    )
}

pub fn with_java_early_return<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_early_return(
        "java-early-return",
        Language::Java,
        JAVA_EARLY_RETURN_FILES,
        JAVA_EARLY_RETURN_PROCEDURES,
        "src/EarlyReturnFlowFixture.java",
        ExpectedSinkOutcome::NotReached,
        ExpectedSinkOutcome::NotReached,
        1,
        1,
        true,
        execute,
    )
}

pub fn with_typescript_early_return<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_early_return(
        "typescript-early-return",
        Language::TypeScript,
        TYPESCRIPT_EARLY_RETURN_FILES,
        TYPESCRIPT_EARLY_RETURN_PROCEDURES,
        "src/early_return_flow.ts",
        ExpectedSinkOutcome::Inconclusive,
        ExpectedSinkOutcome::Inconclusive,
        3,
        3,
        false,
        execute,
    )
}

pub fn with_java_two_matched_calls<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_two_matched_calls(
        "java-two-matched-calls",
        Language::Java,
        JAVA_TWO_CALL_FILES,
        JAVA_TWO_CALL_PROCEDURES,
        "src/TwoCallFlowFixture.java",
        ExpectedSinkOutcome::NotReached,
        1,
        1,
        true,
        execute,
    )
}

pub fn with_typescript_two_matched_calls<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_two_matched_calls(
        "typescript-two-matched-calls",
        Language::TypeScript,
        TYPESCRIPT_TWO_CALL_FILES,
        TYPESCRIPT_TWO_CALL_PROCEDURES,
        "src/two_call_flow.ts",
        ExpectedSinkOutcome::Inconclusive,
        6,
        4,
        false,
        execute,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_branch_merge<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    sinks: &[CallArgumentSink<'_>],
    path: &str,
    meeting_count: usize,
    public_endpoint_count: usize,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let carriers = [
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
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
            interprocedural: &[],
        },
    }];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: BRANCH_CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_meetings: &meetings,
    })
}

#[allow(clippy::too_many_arguments)]
fn with_early_return<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    clean_outcome: ExpectedSinkOutcome,
    unreachable_outcome: ExpectedSinkOutcome,
    meeting_count: usize,
    public_endpoint_count: usize,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
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
            outcome: clean_outcome,
        },
        CallArgumentSink {
            alias: "unreachable",
            call: "unreachable_sink_call",
            argument: 0,
            outcome: unreachable_outcome,
        },
    ];
    let carriers = [
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
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
            interprocedural: &[],
        },
    }];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: EARLY_RETURN_CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_meetings: &meetings,
    })
}

#[allow(clippy::too_many_arguments)]
fn with_two_matched_calls<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    clean_outcome: ExpectedSinkOutcome,
    meeting_count: usize,
    public_endpoint_count: usize,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
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
            outcome: clean_outcome,
        },
    ];
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
            snippet: "first".into(),
        },
        CarrierMilestone::CallArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "relay".into(),
            call: "relay(first)".into(),
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
            call: "relay(first)".into(),
            result: ValueFlowPortKey::NormalReturn,
        },
        CarrierMilestone::Value {
            path: path.into(),
            procedure: "run".into(),
            role: "local".into(),
            ordinal: None,
            snippet: "second".into(),
        },
        CarrierMilestone::SinkArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: "sink(second, clean)".into(),
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
            interprocedural: TWO_CALL_INTERPROCEDURAL,
        },
    }];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: TWO_CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_meetings: &meetings,
    })
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
