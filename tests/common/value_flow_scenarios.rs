//! Shared source-backed value-flow scenario descriptions.
//!
//! Each scenario is materialized through a closure so its expected witness can
//! borrow locally constructed carrier milestones without leaking test-run
//! state. Direct and public-query executors receive the exact same case value.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::dataflow::{PathQuality, SemanticInputStatus};
use brokk_bifrost::analyzer::semantic::{IcfgEdgeKind, ProcedureKind, SemanticCapability};
use brokk_bifrost::analyzer::value_flow::{
    DIRECT_VALUE_FLOW_READY_LANGUAGES, ValueFlowMayStatus, ValueFlowMustStatus, ValueFlowPortKey,
};

use crate::value_flow_conformance::{
    CallArgumentSink, CallSelector, CarrierMilestone, ExpectedLocationRelation, ExpectedMeeting,
    ExpectedSinkOutcome, ExpectedWitness, InlineSourceFile, InterproceduralMilestone,
    ParameterSource, ProcedureSelector, RelationLocationSide, SelectorMilestone,
    ValueFlowConformanceCase,
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

const JAVA_SPLIT_RELAY_SOURCE: &str = r#"
final class SplitRelay {
  static String relay(String value) {
    String relayed = value;
    return relayed;
  }
}
"#;

const JAVA_SPLIT_CALLER_SOURCE: &str = r#"
final class SplitFlowFixture {
  static void sink(String flowed, String clean) {}

  static void run(String input) {
    String copy = SplitRelay.relay(input);
    String clean = "clean";
    sink(copy, clean);
  }
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

const JAVA_RECEIVER_SOURCE: &str = r#"
final class ReceiverFlowFixture {
  ReceiverFlowFixture relay() {
    return this;
  }

  static void sink(ReceiverFlowFixture flowed, Object clean) {}

  static void run(ReceiverFlowFixture input) {
    ReceiverFlowFixture copy = input.relay();
    Object clean = new Object();
    sink(copy, clean);
  }
}
"#;

const TYPESCRIPT_RECEIVER_SOURCE: &str = r#"
class ReceiverFlowFixture {
  relay(): ReceiverFlowFixture {
    return this;
  }
}

function sink(flowed: ReceiverFlowFixture, clean: object): void {}

function run(input: ReceiverFlowFixture): void {
  const copy = input.relay();
  const clean = {};
  sink(copy, clean);
}
"#;

const JAVA_EXCEPTIONAL_SOURCE: &str = r#"
final class ExceptionalFlowFixture {
  static RuntimeException fail(RuntimeException value) {
    throw value;
  }

  static void sink(RuntimeException flowed, Object clean) {}

  static void run(RuntimeException input) {
    Object clean = new Object();
    try {
      fail(input);
    } catch (RuntimeException failure) {
      sink(input, clean);
    }
  }
}
"#;

const TYPESCRIPT_EXCEPTIONAL_SOURCE: &str = r#"
function fail(value: Error): never {
  throw value;
}

function sink(flowed: Error, clean: object): void {}

function run(input: Error): void {
  const clean = {};
  try {
    fail(input);
  } catch (failure) {
    sink(input, clean);
  }
}
"#;

const JAVA_CLEANUP_SOURCE: &str = r#"
final class CleanupFlowFixture {
  static String relay(String value) {
    String relayed = value;
    return relayed;
  }

  static void sink(String flowed, String clean) {}

  static void run(String input) {
    String copy = "clean";
    String clean = "clean";
    try {
      copy = relay(input);
    } finally {
      sink(copy, clean);
    }
  }
}
"#;

const TYPESCRIPT_CLEANUP_SOURCE: &str = r#"
function relay(value: string): string {
  const relayed = value;
  return relayed;
}

function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  let copy = "clean";
  const clean = "clean";
  try {
    copy = relay(input);
  } finally {
    sink(copy, clean);
  }
}
"#;

const JAVA_CAPTURE_SOURCE: &str = r#"
final class CaptureFlowFixture {
  static void sink(String flowed, String clean) {}

  static void run(String input) {
    String anchor = input;
    Runnable callback = () -> {
      String copy = input;
      String clean = "clean";
      sink(copy, clean);
    };
    callback.run();
  }
}
"#;

const TYPESCRIPT_CAPTURE_SOURCE: &str = r#"
function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  const anchor = input;
  const callback = () => {
    const copy = input;
    const clean = "clean";
    sink(copy, clean);
  };
  callback();
  void anchor;
}
"#;

const JAVA_FIELD_ACCESS_SOURCE: &str = r#"
final class FieldFlowFixture {
  static final class Box {
    String value;
  }

  static void sink(String flowed, String clean) {}

  static void run(String input) {
    Box box = new Box();
    box.value = input;
    String copy = box.value;
    String clean = "clean";
    sink(copy, clean);
  }
}
"#;

const TYPESCRIPT_FIELD_ACCESS_SOURCE: &str = r#"
class Box {
  value: string = "clean";
}

function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  const box = new Box();
  box.value = input;
  const copy = box.value;
  const clean = "clean";
  sink(copy, clean);
}
"#;

const JAVA_FIELD_ALIAS_SOURCE: &str = r#"
final class FieldAliasFlowFixture {
  static final class Box {
    String value;
  }

  static void sink(String flowed, String clean) {}

  static void run(String input) {
    Box box = new Box();
    Box alias = box;
    alias.value = input;
    String copy = box.value;
    String clean = "clean";
    sink(copy, clean);
  }
}
"#;

const TYPESCRIPT_FIELD_ALIAS_SOURCE: &str = r#"
class Box {
  value: string = "clean";
}

function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  const box = new Box();
  const alias = box;
  alias.value = input;
  const copy = box.value;
  const clean = "clean";
  sink(copy, clean);
}
"#;

const JAVA_OVER_BOUND_FIELD_SOURCE: &str = r#"
final class OverBoundFieldFlowFixture {
  static final class Box {
    Box next;
    String value;
  }

  static void sink(String flowed, String clean) {}

  static void run(String input) {
    Box box = new Box();
    box.next.next.next.next.next.next.next.next.value = input;
    String copy = box.next.next.next.next.next.next.next.next.value;
    String clean = "clean";
    sink(copy, clean);
  }
}
"#;

const TYPESCRIPT_OVER_BOUND_FIELD_SOURCE: &str = r#"
class OverBoundBox {
  next!: OverBoundBox;
  value: string = "clean";
}

function sink(flowed: string, clean: string): void {}

function run(input: string): void {
  const box = new OverBoundBox();
  box.next.next.next.next.next.next.next.next.value = input;
  const copy = box.next.next.next.next.next.next.next.next.value;
  const clean = "clean";
  sink(copy, clean);
}
"#;

const JAVA_INDEX_ACCESS_SOURCE: &str = r#"
final class IndexFlowFixture {
  static void sink(String flowed, String wrong) {}

  static void run(String input) {
    String[] values = new String[2];
    values[0] = input;
    String copy = values[0];
    String wrong = values[1];
    sink(copy, wrong);
  }
}
"#;

const TYPESCRIPT_INDEX_ACCESS_SOURCE: &str = r#"
function sink(flowed: string, wrong: string): void {}

function run(input: string): void {
  const values = ["clean", "clean"];
  values[0] = input;
  const copy = values[0];
  const wrong = values[1];
  sink(copy, wrong);
}
"#;

const JAVA_UNRESOLVED_CALL_SOURCE: &str = r#"
interface ExternalWork {
  String relay(String value);
}

final class UnresolvedCallFlowFixture {
  static void sink(String flowed, String unresolved) {}

  static void run(ExternalWork work, String input) {
    sink(input, "clean");
    String copy = work.relay(input);
    sink("clean", copy);
  }
}
"#;

const TYPESCRIPT_UNRESOLVED_CALL_SOURCE: &str = r#"
interface ExternalWork {
  relay(value: string): string;
}

function sink(flowed: string, unresolved: string): void {}

function run(work: ExternalWork, input: string): void {
  sink(input, "clean");
  const copy = work.relay(input);
  sink("clean", copy);
}
"#;

const JAVA_AMBIGUOUS_A_SOURCE: &str = r#"
package a;
public final class A {
  public static String relay(String value) { return value; }
}
"#;

const JAVA_AMBIGUOUS_B_SOURCE: &str = r#"
package b;
public final class B {
  public static String relay(String value) { return value; }
}
"#;

const JAVA_AMBIGUOUS_CALL_SOURCE: &str = r#"
import static a.A.relay;
import static b.B.relay;

final class AmbiguousCallFlowFixture {
  static void sink(String flowed, String ambiguous) {}

  static void run(String input) {
    sink(input, "clean");
    String copy = relay("clean");
    sink("clean", copy);
  }
}
"#;

const TYPESCRIPT_AMBIGUOUS_A_SOURCE: &str = r#"
export function relay(value: string): string { return value; }
"#;

const TYPESCRIPT_AMBIGUOUS_B_SOURCE: &str = r#"
export function relay(value: string): string { return value; }
"#;

const TYPESCRIPT_AMBIGUOUS_CALL_SOURCE: &str = r#"
import { relay } from "./a";
import { relay } from "./b";

function sink(flowed: string, ambiguous: string): void {}

function run(input: string): void {
  sink(input, "clean");
  const copy = relay("clean");
  sink("clean", copy);
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

const JAVA_SPLIT_FILES: &[InlineSourceFile<'_>] = &[
    InlineSourceFile {
        path: "src/SplitRelay.java",
        source: JAVA_SPLIT_RELAY_SOURCE,
    },
    InlineSourceFile {
        path: "src/SplitFlowFixture.java",
        source: JAVA_SPLIT_CALLER_SOURCE,
    },
];

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

const JAVA_RECEIVER_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/ReceiverFlowFixture.java",
    source: JAVA_RECEIVER_SOURCE,
}];

const TYPESCRIPT_RECEIVER_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/receiver_flow.ts",
    source: TYPESCRIPT_RECEIVER_SOURCE,
}];

const JAVA_EXCEPTIONAL_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/ExceptionalFlowFixture.java",
    source: JAVA_EXCEPTIONAL_SOURCE,
}];

const TYPESCRIPT_EXCEPTIONAL_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/exceptional_flow.ts",
    source: TYPESCRIPT_EXCEPTIONAL_SOURCE,
}];

const JAVA_CLEANUP_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/CleanupFlowFixture.java",
    source: JAVA_CLEANUP_SOURCE,
}];

const TYPESCRIPT_CLEANUP_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/cleanup_flow.ts",
    source: TYPESCRIPT_CLEANUP_SOURCE,
}];

const JAVA_CAPTURE_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/CaptureFlowFixture.java",
    source: JAVA_CAPTURE_SOURCE,
}];

const TYPESCRIPT_CAPTURE_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/capture_flow.ts",
    source: TYPESCRIPT_CAPTURE_SOURCE,
}];

const JAVA_FIELD_ACCESS_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/FieldFlowFixture.java",
    source: JAVA_FIELD_ACCESS_SOURCE,
}];

const TYPESCRIPT_FIELD_ACCESS_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/field_flow.ts",
    source: TYPESCRIPT_FIELD_ACCESS_SOURCE,
}];

const JAVA_FIELD_ALIAS_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/FieldAliasFlowFixture.java",
    source: JAVA_FIELD_ALIAS_SOURCE,
}];

const TYPESCRIPT_FIELD_ALIAS_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/field_alias_flow.ts",
    source: TYPESCRIPT_FIELD_ALIAS_SOURCE,
}];

const JAVA_UNRESOLVED_CALL_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/UnresolvedCallFlowFixture.java",
    source: JAVA_UNRESOLVED_CALL_SOURCE,
}];

const TYPESCRIPT_UNRESOLVED_CALL_FILES: &[InlineSourceFile<'_>] = &[InlineSourceFile {
    path: "src/unresolved_call_flow.ts",
    source: TYPESCRIPT_UNRESOLVED_CALL_SOURCE,
}];

const JAVA_AMBIGUOUS_CALL_FILES: &[InlineSourceFile<'_>] = &[
    InlineSourceFile {
        path: "src/a/A.java",
        source: JAVA_AMBIGUOUS_A_SOURCE,
    },
    InlineSourceFile {
        path: "src/b/B.java",
        source: JAVA_AMBIGUOUS_B_SOURCE,
    },
    InlineSourceFile {
        path: "src/AmbiguousCallFlowFixture.java",
        source: JAVA_AMBIGUOUS_CALL_SOURCE,
    },
];

const TYPESCRIPT_AMBIGUOUS_CALL_FILES: &[InlineSourceFile<'_>] = &[
    InlineSourceFile {
        path: "src/a.ts",
        source: TYPESCRIPT_AMBIGUOUS_A_SOURCE,
    },
    InlineSourceFile {
        path: "src/b.ts",
        source: TYPESCRIPT_AMBIGUOUS_B_SOURCE,
    },
    InlineSourceFile {
        path: "src/ambiguous_call_flow.ts",
        source: TYPESCRIPT_AMBIGUOUS_CALL_SOURCE,
    },
];

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

const JAVA_SPLIT_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/SplitFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/SplitRelay.java",
        name: "relay",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/SplitFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
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

const JAVA_RECEIVER_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/ReceiverFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/ReceiverFlowFixture.java",
        name: "relay",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/ReceiverFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_RECEIVER_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/receiver_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/receiver_flow.ts",
        name: "relay",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/receiver_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_EXCEPTIONAL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/ExceptionalFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "fail",
        path: "src/ExceptionalFlowFixture.java",
        name: "fail",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/ExceptionalFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_EXCEPTIONAL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/exceptional_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "fail",
        path: "src/exceptional_flow.ts",
        name: "fail",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/exceptional_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_CLEANUP_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/CleanupFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/CleanupFlowFixture.java",
        name: "relay",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/CleanupFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_CLEANUP_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/cleanup_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "relay",
        path: "src/cleanup_flow.ts",
        name: "relay",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/cleanup_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_CAPTURE_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/CaptureFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "callback",
        path: "src/CaptureFlowFixture.java",
        name: "callback",
        kind: ProcedureKind::Lambda,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/CaptureFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_CAPTURE_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/capture_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "callback",
        path: "src/capture_flow.ts",
        name: "callback",
        kind: ProcedureKind::Lambda,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/capture_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_FIELD_ACCESS_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/FieldFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/FieldFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_FIELD_ACCESS_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/field_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/field_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_FIELD_ALIAS_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/FieldAliasFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/FieldAliasFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_FIELD_ALIAS_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/field_alias_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/field_alias_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_UNRESOLVED_CALL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/UnresolvedCallFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/UnresolvedCallFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_UNRESOLVED_CALL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/unresolved_call_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/unresolved_call_flow.ts",
        name: "sink",
        kind: ProcedureKind::Function,
    },
];

const JAVA_AMBIGUOUS_CALL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/AmbiguousCallFlowFixture.java",
        name: "run",
        kind: ProcedureKind::Method,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/AmbiguousCallFlowFixture.java",
        name: "sink",
        kind: ProcedureKind::Method,
    },
];

const TYPESCRIPT_AMBIGUOUS_CALL_PROCEDURES: &[ProcedureSelector<'_>] = &[
    ProcedureSelector {
        alias: "run",
        path: "src/ambiguous_call_flow.ts",
        name: "run",
        kind: ProcedureKind::Function,
    },
    ProcedureSelector {
        alias: "sink",
        path: "src/ambiguous_call_flow.ts",
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

const RECEIVER_CALLS: &[CallSelector<'_>] = &[
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

const EXCEPTIONAL_CALLS: &[CallSelector<'_>] = &[
    CallSelector {
        alias: "fail_call",
        caller: "run",
        callee: "fail",
        occurrence: 0,
    },
    CallSelector {
        alias: "sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 0,
    },
];

const CAPTURE_CALLS: &[CallSelector<'_>] = &[CallSelector {
    alias: "sink_call",
    caller: "callback",
    callee: "sink",
    occurrence: 0,
}];

const UNRESOLVED_CALLS: &[CallSelector<'_>] = &[
    CallSelector {
        alias: "preserved_sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 0,
    },
    CallSelector {
        alias: "unresolved_sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 1,
    },
];

const AMBIGUOUS_CALLS: &[CallSelector<'_>] = &[
    CallSelector {
        alias: "preserved_sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 0,
    },
    CallSelector {
        alias: "ambiguous_sink_call",
        caller: "run",
        callee: "sink",
        occurrence: 1,
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

const REACHED_FLOW_INCONCLUSIVE_CLEAN_SINKS: &[CallArgumentSink<'_>] = &[
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

macro_rules! direct_ready_value_flow_scenario_entries {
    ($consumer:ident) => {
        $consumer! {
            (Java, java_exact_helper_flow, java_helper_scenario_runs_through_direct_and_public_queries),
            (TypeScript, typescript_exact_helper_flow, typescript_helper_scenario_runs_through_direct_and_public_queries),
            (JavaScript, javascript_exact_helper_flow, javascript_helper_scenario_runs_through_direct_and_public_queries),
            (Go, go_exact_helper_flow, go_helper_scenario_runs_through_direct_and_public_queries),
            (Php, php_exact_helper_flow, php_helper_scenario_runs_through_direct_and_public_queries),
            (Ruby, ruby_exact_helper_flow, ruby_helper_scenario_runs_through_direct_and_public_queries),
            (CSharp, csharp_exact_helper_flow, csharp_helper_scenario_runs_through_direct_and_public_queries),
            (Rust, rust_exact_helper_flow, rust_helper_scenario_runs_through_direct_and_public_queries),
            (Python, python_exact_helper_flow, python_helper_scenario_runs_through_direct_and_public_queries),
            (Scala, scala_exact_helper_flow, scala_helper_scenario_runs_through_direct_and_public_queries),
            (Kotlin, kotlin_exact_helper_flow, kotlin_helper_scenario_runs_through_direct_and_public_queries),
            (C, c_exact_helper_flow_through_header_declaration, c_helper_scenario_runs_through_direct_and_public_queries),
            (Cpp, cpp_exact_helper_flow_through_header_declaration, cpp_helper_scenario_runs_through_direct_and_public_queries),
        }
    };
}
pub(crate) use direct_ready_value_flow_scenario_entries;

macro_rules! define_direct_ready_value_flow_scenarios {
    ($(($scenario:ident, $direct_test:ident, $public_test:ident),)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum DirectReadyValueFlowScenario {
            $($scenario,)*
        }

        pub const DIRECT_READY_VALUE_FLOW_SCENARIOS: [DirectReadyValueFlowScenario; 13] = [
            $(DirectReadyValueFlowScenario::$scenario,)*
        ];

        impl DirectReadyValueFlowScenario {
            pub const fn language(self) -> Language {
                match self {
                    Self::Java => Language::Java,
                    Self::TypeScript => Language::TypeScript,
                    Self::JavaScript => Language::JavaScript,
                    Self::Go => Language::Go,
                    Self::Php => Language::Php,
                    Self::Ruby => Language::Ruby,
                    Self::CSharp => Language::CSharp,
                    Self::Rust => Language::Rust,
                    Self::Python => Language::Python,
                    Self::Scala => Language::Scala,
                    Self::Kotlin => Language::Kotlin,
                    Self::C | Self::Cpp => Language::Cpp,
                }
            }

            pub fn with_case<T>(
                self,
                execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
            ) -> T {
                match self {
                    Self::Java => with_java_exact_helper(execute),
                    Self::TypeScript => with_typescript_exact_helper(execute),
                    Self::JavaScript => with_javascript_exact_helper(execute),
                    Self::Go => with_go_exact_helper(execute),
                    Self::Php => with_php_exact_helper(execute),
                    Self::Ruby => with_ruby_exact_helper(execute),
                    Self::CSharp => with_csharp_exact_helper(execute),
                    Self::Rust => with_rust_exact_helper(execute),
                    Self::Python => with_python_exact_helper(execute),
                    Self::Scala => with_scala_exact_helper(execute),
                    Self::Kotlin => with_kotlin_exact_helper(execute),
                    Self::C => with_c_exact_helper(execute),
                    Self::Cpp => with_cpp_exact_helper(execute),
                }
            }
        }
    };
}
direct_ready_value_flow_scenario_entries!(define_direct_ready_value_flow_scenarios);

pub fn assert_direct_ready_value_flow_scenario_inventory() {
    let mut languages = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut scenarios_per_language = BTreeMap::<Language, usize>::new();

    for scenario in DIRECT_READY_VALUE_FLOW_SCENARIOS {
        scenario.with_case(|case| {
            assert_eq!(scenario.language(), case.language, "{} language", case.name);
            assert!(
                names.insert(case.name.to_owned()),
                "duplicate scenario {}",
                case.name
            );
            languages.insert(case.language);
            *scenarios_per_language.entry(case.language).or_default() += 1;

            assert!(
                case.sinks
                    .iter()
                    .any(|sink| sink.outcome == ExpectedSinkOutcome::Reached),
                "{} must include a reached sink",
                case.name
            );
            assert!(
                case.sinks
                    .iter()
                    .any(|sink| sink.outcome != ExpectedSinkOutcome::Reached),
                "{} must include a clean or typed-incomplete sink",
                case.name
            );
        });
    }

    assert_eq!(DIRECT_READY_VALUE_FLOW_SCENARIOS.len(), 13);
    assert_eq!(
        languages,
        DIRECT_VALUE_FLOW_READY_LANGUAGES.into_iter().collect()
    );
    for language in DIRECT_VALUE_FLOW_READY_LANGUAGES {
        let expected = if language == Language::Cpp { 2 } else { 1 };
        assert_eq!(
            scenarios_per_language.get(&language),
            Some(&expected),
            "{language:?} scenario count"
        );
    }
    assert!(names.contains("c"));
    assert!(names.contains("cpp"));
}

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

const EXCEPTIONAL_INTERPROCEDURAL: &[InterproceduralMilestone<'_>] = &[InterproceduralMilestone {
    kind: IcfgEdgeKind::CallToExceptionalContinuation,
    source_procedure: "run",
    target_procedure: "run",
    origin_call: "fail_call",
}];

pub fn with_java_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_exact_helper(
        "java",
        Language::Java,
        JAVA_FILES,
        JAVA_PROCEDURES,
        JAVA_SINKS,
        "src/ExactFlowFixture.java",
        "src/ExactFlowFixture.java",
        "relay(input)",
        1,
        1,
        SemanticInputStatus::Unknown,
        false,
        true,
        execute,
    )
}

pub fn with_java_split_exact_helper<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_exact_helper(
        "java-split",
        Language::Java,
        JAVA_SPLIT_FILES,
        JAVA_SPLIT_PROCEDURES,
        JAVA_SINKS,
        "src/SplitFlowFixture.java",
        "src/SplitRelay.java",
        "SplitRelay.relay(input)",
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
        REACHED_FLOW_INCONCLUSIVE_CLEAN_SINKS,
        "src/exact_flow.ts",
        "src/exact_flow.ts",
        "relay(input)",
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
        REACHED_FLOW_INCONCLUSIVE_CLEAN_SINKS,
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
        REACHED_FLOW_INCONCLUSIVE_CLEAN_SINKS,
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

pub fn with_java_receiver_flow<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_receiver_flow(
        "java-receiver-flow",
        Language::Java,
        JAVA_RECEIVER_FILES,
        JAVA_RECEIVER_PROCEDURES,
        "src/ReceiverFlowFixture.java",
        ExpectedSinkOutcome::Inconclusive,
        1,
        1,
        ValueFlowMayStatus::Proven,
        EXPECTED_PATH_QUALITIES,
        ValueFlowMayStatus::Unproven,
        PathQuality::UNPROVEN_PARTIAL,
        SemanticInputStatus::Unknown,
        false,
        execute,
    )
}

pub fn with_typescript_receiver_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_receiver_flow(
        "typescript-receiver-flow",
        Language::TypeScript,
        TYPESCRIPT_RECEIVER_FILES,
        TYPESCRIPT_RECEIVER_PROCEDURES,
        "src/receiver_flow.ts",
        ExpectedSinkOutcome::Inconclusive,
        6,
        4,
        ValueFlowMayStatus::Proven,
        EXPECTED_PATH_QUALITIES,
        ValueFlowMayStatus::Proven,
        PathQuality::PROVEN_COMPLETE,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        false,
        execute,
    )
}

pub fn with_java_exceptional_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    execute(&ValueFlowConformanceCase {
        name: "java-exceptional-flow-unsupported",
        language: Language::Java,
        files: JAVA_EXCEPTIONAL_FILES,
        procedures: JAVA_EXCEPTIONAL_PROCEDURES,
        root: "run",
        calls: EXCEPTIONAL_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &[],
    })
}

pub fn with_typescript_exceptional_flow<T>(
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
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    with_exceptional_flow(
        "typescript-exceptional-flow",
        Language::TypeScript,
        TYPESCRIPT_EXCEPTIONAL_FILES,
        TYPESCRIPT_EXCEPTIONAL_PROCEDURES,
        &sinks,
        "src/exceptional_flow.ts",
        3,
        3,
        false,
        execute,
    )
}

pub fn with_java_cleanup_flow<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    execute(&ValueFlowConformanceCase {
        name: "java-cleanup-flow-unsupported",
        language: Language::Java,
        files: JAVA_CLEANUP_FILES,
        procedures: JAVA_CLEANUP_PROCEDURES,
        root: "run",
        calls: CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &[],
    })
}

pub fn with_typescript_cleanup_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    execute(&ValueFlowConformanceCase {
        name: "typescript-cleanup-flow-unsupported",
        language: Language::TypeScript,
        files: TYPESCRIPT_CLEANUP_FILES,
        procedures: TYPESCRIPT_CLEANUP_PROCEDURES,
        root: "run",
        calls: CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &[],
    })
}

pub fn with_java_capture_flow<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_capture_flow(
        "java-capture-flow",
        Language::Java,
        JAVA_CAPTURE_FILES,
        JAVA_CAPTURE_PROCEDURES,
        "src/CaptureFlowFixture.java",
        SemanticInputStatus::Unknown,
        false,
        execute,
    )
}

pub fn with_typescript_capture_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_capture_flow(
        "typescript-capture-flow",
        Language::TypeScript,
        TYPESCRIPT_CAPTURE_FILES,
        TYPESCRIPT_CAPTURE_PROCEDURES,
        "src/capture_flow.ts",
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        false,
        execute,
    )
}

pub fn with_java_field_access_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_field_access_flow(
        "java-field-access-flow",
        Language::Java,
        JAVA_FIELD_ACCESS_FILES,
        JAVA_FIELD_ACCESS_PROCEDURES,
        "src/FieldFlowFixture.java",
        false,
        execute,
    )
}

pub fn with_typescript_field_access_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_field_access_flow(
        "typescript-field-access-flow",
        Language::TypeScript,
        TYPESCRIPT_FIELD_ACCESS_FILES,
        TYPESCRIPT_FIELD_ACCESS_PROCEDURES,
        "src/field_flow.ts",
        false,
        execute,
    )
}

pub fn with_java_over_bound_field_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let files = [InlineSourceFile {
        path: "src/OverBoundFieldFlowFixture.java",
        source: JAVA_OVER_BOUND_FIELD_SOURCE,
    }];
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path: files[0].path,
            name: "run",
            kind: ProcedureKind::Method,
        },
        ProcedureSelector {
            alias: "sink",
            path: files[0].path,
            name: "sink",
            kind: ProcedureKind::Method,
        },
    ];
    with_over_bound_field_access_flow(
        "java-over-bound-field-flow",
        Language::Java,
        &files,
        &procedures,
        files[0].path,
        SemanticInputStatus::Unknown,
        execute,
    )
}

pub fn with_typescript_over_bound_field_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let files = [InlineSourceFile {
        path: "src/over_bound_field_flow.ts",
        source: TYPESCRIPT_OVER_BOUND_FIELD_SOURCE,
    }];
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path: files[0].path,
            name: "run",
            kind: ProcedureKind::Function,
        },
        ProcedureSelector {
            alias: "sink",
            path: files[0].path,
            name: "sink",
            kind: ProcedureKind::Function,
        },
    ];
    with_over_bound_field_access_flow(
        "typescript-over-bound-field-flow",
        Language::TypeScript,
        &files,
        &procedures,
        files[0].path,
        SemanticInputStatus::Unknown,
        execute,
    )
}

pub fn with_java_index_access_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let files = [InlineSourceFile {
        path: "src/IndexFlowFixture.java",
        source: JAVA_INDEX_ACCESS_SOURCE,
    }];
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path: files[0].path,
            name: "run",
            kind: ProcedureKind::Method,
        },
        ProcedureSelector {
            alias: "sink",
            path: files[0].path,
            name: "sink",
            kind: ProcedureKind::Method,
        },
    ];
    with_index_access_flow(
        "java-index-access-flow",
        Language::Java,
        &files,
        &procedures,
        files[0].path,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        execute,
    )
}

pub fn with_typescript_index_access_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let files = [InlineSourceFile {
        path: "src/index_flow.ts",
        source: TYPESCRIPT_INDEX_ACCESS_SOURCE,
    }];
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path: files[0].path,
            name: "run",
            kind: ProcedureKind::Function,
        },
        ProcedureSelector {
            alias: "sink",
            path: files[0].path,
            name: "sink",
            kind: ProcedureKind::Function,
        },
    ];
    with_index_access_flow(
        "typescript-index-access-flow",
        Language::TypeScript,
        &files,
        &procedures,
        files[0].path,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        execute,
    )
}

pub fn with_java_field_alias_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_inconclusive_parameter_flow(
        "java-field-alias-flow",
        Language::Java,
        JAVA_FIELD_ALIAS_FILES,
        JAVA_FIELD_ALIAS_PROCEDURES,
        "run",
        BRANCH_CALLS,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        false,
        execute,
    )
}

pub fn with_typescript_field_alias_flow<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_inconclusive_parameter_flow(
        "typescript-field-alias-flow",
        Language::TypeScript,
        TYPESCRIPT_FIELD_ALIAS_FILES,
        TYPESCRIPT_FIELD_ALIAS_PROCEDURES,
        "run",
        BRANCH_CALLS,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        false,
        execute,
    )
}

pub fn with_java_unresolved_call_negative<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_unresolved_call_negative(
        "java-unresolved-call-negative",
        Language::Java,
        JAVA_UNRESOLVED_CALL_FILES,
        JAVA_UNRESOLVED_CALL_PROCEDURES,
        "src/UnresolvedCallFlowFixture.java",
        SemanticInputStatus::Unknown,
        execute,
    )
}

pub fn with_typescript_unresolved_call_negative<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_unresolved_call_negative(
        "typescript-unresolved-call-negative",
        Language::TypeScript,
        TYPESCRIPT_UNRESOLVED_CALL_FILES,
        TYPESCRIPT_UNRESOLVED_CALL_PROCEDURES,
        "src/unresolved_call_flow.ts",
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        execute,
    )
}

pub fn with_java_ambiguous_call_negative<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_ambiguous_call_negative(
        "java-ambiguous-call-negative",
        Language::Java,
        JAVA_AMBIGUOUS_CALL_FILES,
        JAVA_AMBIGUOUS_CALL_PROCEDURES,
        "src/AmbiguousCallFlowFixture.java",
        SemanticInputStatus::Unknown,
        execute,
    )
}

pub fn with_typescript_ambiguous_call_negative<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_ambiguous_call_negative(
        "typescript-ambiguous-call-negative",
        Language::TypeScript,
        TYPESCRIPT_AMBIGUOUS_CALL_FILES,
        TYPESCRIPT_AMBIGUOUS_CALL_PROCEDURES,
        "src/ambiguous_call_flow.ts",
        SemanticInputStatus::Unknown,
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
        public_may_complete_count: 0,
        public_may_partial_count: if language == Language::TypeScript {
            public_endpoint_count.saturating_sub(1)
        } else {
            0
        },
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
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
        public_may_complete_count: 0,
        public_may_partial_count: if language == Language::TypeScript {
            public_endpoint_count.saturating_sub(1)
        } else {
            0
        },
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
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
    let public_may_complete_count = usize::from(language == Language::TypeScript);
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
        public_may_complete_count,
        public_may_partial_count: if language == Language::TypeScript {
            public_endpoint_count.saturating_sub(1 + public_may_complete_count)
        } else {
            0
        },
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &meetings,
    })
}

#[allow(clippy::too_many_arguments)]
fn with_receiver_flow<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    clean_outcome: ExpectedSinkOutcome,
    meeting_count: usize,
    public_endpoint_count: usize,
    may_status: ValueFlowMayStatus,
    path_qualities: &[PathQuality],
    witness_may_status: ValueFlowMayStatus,
    witness_path_quality: PathQuality,
    expected_discovery_status: SemanticInputStatus,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let public_may_complete_count = usize::from(language == Language::TypeScript);
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
    let carriers = [
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
        },
        CarrierMilestone::CallReceiver {
            path: path.into(),
            caller: "run".into(),
            callee: "relay".into(),
            call: "input.relay()".into(),
        },
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "relay".into(),
            kind: ValueFlowPortKey::Receiver,
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
            call: "input.relay()".into(),
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
        may_status,
        public_may_complete_count,
        public_may_partial_count: if language == Language::TypeScript {
            public_endpoint_count.saturating_sub(1 + public_may_complete_count)
        } else {
            0
        },
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities,
        witness: ExpectedWitness {
            truncated: false,
            may_status: witness_may_status,
            path_quality: witness_path_quality,
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
        calls: RECEIVER_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &meetings,
    })
}

#[allow(clippy::too_many_arguments)]
fn with_exceptional_flow<T>(
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
        CarrierMilestone::SinkArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: "sink(input, clean)".into(),
            ordinal: 0,
        },
    ];
    let meetings = [ExpectedMeeting {
        sink: "flowed",
        meeting_count,
        public_endpoint_count,
        may_status: ValueFlowMayStatus::Proven,
        public_may_complete_count: 0,
        public_may_partial_count: if language == Language::TypeScript {
            public_endpoint_count.saturating_sub(1)
        } else {
            0
        },
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Unproven,
            path_quality: PathQuality::UNPROVEN_PARTIAL,
            carriers: &carriers,
            interprocedural: EXCEPTIONAL_INTERPROCEDURAL,
        },
    }];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: EXCEPTIONAL_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks,
        expected_discovery_status: SemanticInputStatus::Unknown,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &meetings,
    })
}

#[allow(clippy::too_many_arguments)]
fn with_capture_flow<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    _path: &str,
    expected_discovery_status: SemanticInputStatus,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_inconclusive_parameter_flow(
        name,
        language,
        files,
        procedures,
        "run",
        CAPTURE_CALLS,
        expected_discovery_status,
        expected_result_complete,
        execute,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_inconclusive_parameter_flow<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    root: &str,
    calls: &[CallSelector<'_>],
    expected_discovery_status: SemanticInputStatus,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root,
        calls,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &[],
    })
}

#[allow(clippy::too_many_arguments)]
fn with_field_access_flow<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    let location = CarrierMilestone::Location {
        root: Box::new(CarrierMilestone::Value {
            path: path.into(),
            procedure: "run".into(),
            role: "temporary".into(),
            ordinal: None,
            snippet: "box".into(),
        }),
        selectors: vec![SelectorMilestone::Field {
            path: path.into(),
            procedure: "run".into(),
            snippet: "value".into(),
        }]
        .into_boxed_slice(),
        exact: true,
    };
    let expected_location_relations = [
        ExpectedLocationRelation {
            procedure: "run",
            kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryStore,
            side: RelationLocationSide::Target,
            location: &location,
        },
        ExpectedLocationRelation {
            procedure: "run",
            kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryLoad,
            side: RelationLocationSide::Source,
            location: &location,
        },
    ];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: BRANCH_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status: SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &expected_location_relations,
        expected_meetings: &[],
    })
}

fn with_over_bound_field_access_flow<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    expected_discovery_status: SemanticInputStatus,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    let location = |selector_count: usize, exact: bool| CarrierMilestone::Location {
        root: Box::new(CarrierMilestone::Value {
            path: path.into(),
            procedure: "run".into(),
            role: "temporary".into(),
            ordinal: None,
            snippet: "box".into(),
        }),
        selectors: (0..selector_count)
            .map(|_| SelectorMilestone::Field {
                path: path.into(),
                procedure: "run".into(),
                snippet: "next".into(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        exact,
    };
    let exact_receiver_loads = (1..=8)
        .map(|selector_count| location(selector_count, true))
        .collect::<Vec<_>>();
    let summary_location = location(8, false);
    let mut expected_location_relations = Vec::with_capacity(18);
    expected_location_relations.push(ExpectedLocationRelation {
        procedure: "run",
        kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryStore,
        side: RelationLocationSide::Target,
        location: &summary_location,
    });
    expected_location_relations.push(ExpectedLocationRelation {
        procedure: "run",
        kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryLoad,
        side: RelationLocationSide::Source,
        location: &summary_location,
    });
    for receiver in &exact_receiver_loads {
        for _ in 0..2 {
            expected_location_relations.push(ExpectedLocationRelation {
                procedure: "run",
                kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryLoad,
                side: RelationLocationSide::Source,
                location: receiver,
            });
        }
    }
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: BRANCH_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: false,
        expected_location_relations: &expected_location_relations,
        expected_meetings: &[],
    })
}

fn with_index_access_flow<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    expected_discovery_status: SemanticInputStatus,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
        CallArgumentSink {
            alias: "wrong",
            call: "sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    let index_location = |snippet: &str| CarrierMilestone::Location {
        root: Box::new(CarrierMilestone::Value {
            path: path.into(),
            procedure: "run".into(),
            role: "temporary".into(),
            ordinal: None,
            snippet: "values".into(),
        }),
        selectors: vec![SelectorMilestone::ExactIndex(Box::new(
            CarrierMilestone::Value {
                path: path.into(),
                procedure: "run".into(),
                role: "constant".into(),
                ordinal: None,
                snippet: snippet.into(),
            },
        ))]
        .into_boxed_slice(),
        exact: true,
    };
    let index_zero = index_location("0");
    let index_one = index_location("1");
    let expected_location_relations = [
        ExpectedLocationRelation {
            procedure: "run",
            kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryStore,
            side: RelationLocationSide::Target,
            location: &index_zero,
        },
        ExpectedLocationRelation {
            procedure: "run",
            kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryLoad,
            side: RelationLocationSide::Source,
            location: &index_zero,
        },
        ExpectedLocationRelation {
            procedure: "run",
            kind: brokk_bifrost::analyzer::semantic::ValueFlowRelationKind::MemoryLoad,
            side: RelationLocationSide::Source,
            location: &index_one,
        },
    ];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures,
        root: "run",
        calls: BRANCH_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: false,
        expected_location_relations: &expected_location_relations,
        expected_meetings: &[],
    })
}

fn with_unresolved_call_negative<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    expected_discovery_status: SemanticInputStatus,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let meeting_count = if language == Language::TypeScript {
        3
    } else {
        1
    };
    let sinks = [
        CallArgumentSink {
            alias: "preserved",
            call: "preserved_sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Reached,
        },
        CallArgumentSink {
            alias: "unresolved",
            call: "unresolved_sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    let carriers = [
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 1 },
        },
        CarrierMilestone::SinkArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: "sink(input, \"clean\")".into(),
            ordinal: 0,
        },
    ];
    let meetings = [ExpectedMeeting {
        sink: "preserved",
        meeting_count,
        public_endpoint_count: meeting_count,
        may_status: ValueFlowMayStatus::Proven,
        public_may_complete_count: 0,
        public_may_partial_count: meeting_count.saturating_sub(1),
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        calls: UNRESOLVED_CALLS,
        unmodeled_call_behavior:
            brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::RequireModel,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 1,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &meetings,
    })
}

fn with_ambiguous_call_negative<T>(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    procedures: &[ProcedureSelector<'_>],
    path: &str,
    expected_discovery_status: SemanticInputStatus,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let meeting_count = if language == Language::TypeScript {
        3
    } else {
        1
    };
    let sinks = [
        CallArgumentSink {
            alias: "preserved",
            call: "preserved_sink_call",
            argument: 0,
            outcome: ExpectedSinkOutcome::Reached,
        },
        CallArgumentSink {
            alias: "ambiguous",
            call: "ambiguous_sink_call",
            argument: 1,
            outcome: ExpectedSinkOutcome::Inconclusive,
        },
    ];
    let carriers = [
        CarrierMilestone::Port {
            path: path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
        },
        CarrierMilestone::SinkArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: "sink(input, \"clean\")".into(),
            ordinal: 0,
        },
    ];
    let meetings = [ExpectedMeeting {
        sink: "preserved",
        meeting_count,
        public_endpoint_count: meeting_count,
        may_status: ValueFlowMayStatus::Proven,
        public_may_complete_count: 0,
        public_may_partial_count: meeting_count.saturating_sub(1),
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        calls: AMBIGUOUS_CALLS,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete: false,
        expected_public_ambiguous: true,
        expected_location_relations: &[],
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
    run_path: &str,
    relay_path: &str,
    relay_call: &str,
    meeting_count: usize,
    public_endpoint_count: usize,
    expected_discovery_status: SemanticInputStatus,
    expected_discovery_complete: bool,
    expected_result_complete: bool,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let public_may_complete_count = usize::from(language == Language::TypeScript);
    let carriers = vec![
        CarrierMilestone::Port {
            path: run_path.into(),
            procedure: "run".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
        },
        CarrierMilestone::CallArgument {
            path: run_path.into(),
            caller: "run".into(),
            callee: "relay".into(),
            call: relay_call.into(),
            ordinal: 0,
        },
        CarrierMilestone::Port {
            path: relay_path.into(),
            procedure: "relay".into(),
            kind: ValueFlowPortKey::Parameter { ordinal: 0 },
        },
        CarrierMilestone::Value {
            path: relay_path.into(),
            procedure: "relay".into(),
            role: "local".into(),
            ordinal: None,
            snippet: "relayed".into(),
        },
        CarrierMilestone::Port {
            path: relay_path.into(),
            procedure: "relay".into(),
            kind: ValueFlowPortKey::NormalReturn,
        },
        CarrierMilestone::CallResult {
            path: run_path.into(),
            caller: "run".into(),
            callee: "relay".into(),
            call: relay_call.into(),
            result: ValueFlowPortKey::NormalReturn,
        },
        CarrierMilestone::Value {
            path: run_path.into(),
            procedure: "run".into(),
            role: "local".into(),
            ordinal: None,
            snippet: "copy".into(),
        },
        CarrierMilestone::SinkArgument {
            path: run_path.into(),
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
        public_may_complete_count,
        public_may_partial_count: if language == Language::TypeScript {
            public_endpoint_count.saturating_sub(1 + public_may_complete_count)
        } else {
            0
        },
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks,
        expected_discovery_status,
        expected_discovery_complete,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &meetings,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn with_single_file_exact_helper<T>(
    name: &str,
    language: Language,
    path: &str,
    source: &str,
    procedure_kind: ProcedureKind,
    relay_call: &str,
    sink_call: &str,
    relay_local: &str,
    run_local: &str,
    clean_outcome: ExpectedSinkOutcome,
    expected_discovery_status: SemanticInputStatus,
    expected_result_complete: bool,
    meeting_count: usize,
    public_endpoint_count: usize,
    public_may_complete_count: usize,
    public_may_partial_count: usize,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let files = [InlineSourceFile { path, source }];
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path,
            name: "run",
            kind: procedure_kind,
        },
        ProcedureSelector {
            alias: "relay",
            path,
            name: "relay",
            kind: procedure_kind,
        },
        ProcedureSelector {
            alias: "sink",
            path,
            name: "sink",
            kind: procedure_kind,
        },
    ];
    let calls = [
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
            call: relay_call.into(),
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
            snippet: relay_local.into(),
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
            call: relay_call.into(),
            result: ValueFlowPortKey::NormalReturn,
        },
        CarrierMilestone::Value {
            path: path.into(),
            procedure: "run".into(),
            role: "local".into(),
            ordinal: None,
            snippet: run_local.into(),
        },
        CarrierMilestone::SinkArgument {
            path: path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: sink_call.into(),
            ordinal: 0,
        },
    ];
    let interprocedural = [
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
    let meetings = [ExpectedMeeting {
        sink: "flowed",
        meeting_count,
        public_endpoint_count,
        may_status: ValueFlowMayStatus::Proven,
        public_may_complete_count,
        public_may_partial_count,
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
            carriers: &carriers,
            interprocedural: &interprocedural,
        },
    }];
    execute(&ValueFlowConformanceCase {
        name,
        language,
        files: &files,
        procedures: &procedures,
        root: "run",
        calls: &calls,
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete: false,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
        expected_meetings: &meetings,
    })
}

pub fn with_csharp_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "csharp",
        Language::CSharp,
        "csharp/ExactFlowFixture.cs",
        r#"
            namespace Conformance
            {
                public static class Relay
                {
                    public static object relay(object value)
                    {
                        object relayed = value;
                        return relayed;
                    }
                }

                public static class ExactFlowFixture
                {
                    public static void sink(object flowed, object clean) {}

                    public static void run(object input)
                    {
                        object copy = Relay.relay(input);
                        object clean = new object();
                        ExactFlowFixture.sink(copy, clean);
                    }
                }
            }
        "#,
        ProcedureKind::Method,
        "Relay.relay(input)",
        "ExactFlowFixture.sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::NotReached,
        SemanticInputStatus::Unknown,
        true,
        1,
        1,
        0,
        0,
        execute,
    )
}

pub fn with_rust_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "rust",
        Language::Rust,
        "src/lib.rs",
        r#"
            fn relay(value: &str) -> &str {
                let relayed = value;
                relayed
            }

            fn sink(flowed: &str, clean: &str) {}

            fn run(input: &str) {
                let copy = relay(input);
                let clean = "clean";
                sink(copy, clean);
            }
        "#,
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        1,
        1,
        0,
        0,
        execute,
    )
}

pub fn with_python_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "python",
        Language::Python,
        "exact_flow.py",
        r#"
            def relay(value):
                relayed = value
                return relayed

            def sink(flowed, clean):
                pass

            def run(input):
                copy = relay(input)
                clean = "clean"
                sink(copy, clean)
        "#,
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        false,
        6,
        4,
        1,
        2,
        execute,
    )
}

pub fn with_scala_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "scala",
        Language::Scala,
        "src/ExactFlowFixture.scala",
        r#"
            package conformance

            object ExactFlowFixture {
              def relay(value: String): String = {
                val relayed = value
                relayed
              }

              def sink(flowed: String, clean: String): Unit = {}

              def run(input: String): Unit = {
                val copy = ExactFlowFixture.relay(input)
                val clean = "clean"
                ExactFlowFixture.sink(copy, clean)
              }
            }
        "#,
        ProcedureKind::Method,
        "ExactFlowFixture.relay(input)",
        "ExactFlowFixture.sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        1,
        1,
        0,
        0,
        execute,
    )
}

pub fn with_kotlin_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "kotlin",
        Language::Kotlin,
        "src/ExactFlowFixture.kt",
        r#"
            package conformance

            object ExactFlowFixture {
                fun relay(value: String): String {
                    val relayed = value
                    return relayed
                }

                fun sink(flowed: String, clean: String) {}

                fun run(input: String) {
                    val copy = ExactFlowFixture.relay(input)
                    val clean = "clean"
                    ExactFlowFixture.sink(copy, clean)
                }
            }
        "#,
        ProcedureKind::Method,
        "ExactFlowFixture.relay(input)",
        "ExactFlowFixture.sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::NotReached,
        SemanticInputStatus::Unknown,
        true,
        1,
        1,
        0,
        0,
        execute,
    )
}

pub fn with_c_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    let files = [
        InlineSourceFile {
            path: "c/conformance/exact_flow.h",
            source: r#"
                const char *relay(const char *value);
            "#,
        },
        InlineSourceFile {
            path: "c/conformance/exact_flow.c",
            source: r#"
                #include "exact_flow.h"

                const char *relay(const char *value) {
                    const char *relayed = value;
                    return relayed;
                }
            "#,
        },
        InlineSourceFile {
            path: "c/conformance/caller.c",
            source: r#"
                #include "exact_flow.h"

                void sink(const char *flowed, const char *clean) {}

                void run(const char *input) {
                    const char *copy = relay(input);
                    const char *clean = "clean";
                    sink(copy, clean);
                }
            "#,
        },
    ];
    with_c_family_exact_helper(
        "c",
        &files,
        "c/conformance/caller.c",
        "c/conformance/exact_flow.c",
        execute,
    )
}

pub fn with_cpp_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    let files = [
        InlineSourceFile {
            path: "cpp/conformance/exact_flow.hpp",
            source: r#"
                const char *relay(const char *value);
            "#,
        },
        InlineSourceFile {
            path: "cpp/conformance/exact_flow.cpp",
            source: r#"
                #include "exact_flow.hpp"

                const char *relay(const char *value) {
                    const char *relayed = value;
                    return relayed;
                }
            "#,
        },
        InlineSourceFile {
            path: "cpp/conformance/caller.cpp",
            source: r#"
                #include "exact_flow.hpp"

                void sink(const char *flowed, const char *clean) {}

                void run(const char *input) {
                    const char *copy = relay(input);
                    const char *clean = "clean";
                    sink(copy, clean);
                }
            "#,
        },
    ];
    with_c_family_exact_helper(
        "cpp",
        &files,
        "cpp/conformance/caller.cpp",
        "cpp/conformance/exact_flow.cpp",
        execute,
    )
}

fn with_c_family_exact_helper<T>(
    name: &str,
    files: &[InlineSourceFile<'_>],
    run_path: &str,
    relay_path: &str,
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path: run_path,
            name: "run",
            kind: ProcedureKind::Function,
        },
        ProcedureSelector {
            alias: "relay",
            path: relay_path,
            name: "relay",
            kind: ProcedureKind::Function,
        },
        ProcedureSelector {
            alias: "sink",
            path: run_path,
            name: "sink",
            kind: ProcedureKind::Function,
        },
    ];
    with_exact_helper(
        name,
        Language::Cpp,
        files,
        &procedures,
        REACHED_FLOW_INCONCLUSIVE_CLEAN_SINKS,
        run_path,
        relay_path,
        "relay(input)",
        1,
        1,
        SemanticInputStatus::Unknown,
        false,
        false,
        execute,
    )
}

pub fn with_javascript_exact_helper<T>(
    execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T,
) -> T {
    with_single_file_exact_helper(
        "javascript",
        Language::JavaScript,
        "src/exact_flow.js",
        r#"
function relay(value) {
  const relayed = value;
  return relayed;
}
function sink(flowed, clean) {}
function run(input) {
  const copy = relay(input);
  const clean = "clean";
  sink(copy, clean);
}
"#,
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        6,
        4,
        1,
        2,
        execute,
    )
}

pub fn with_go_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "go",
        Language::Go,
        "exact_flow.go",
        r#"
package conformance
func relay(value string) string { relayed := value; return relayed }
func sink(flowed string, clean string) {}
func run(input string) { copy := relay(input); clean := "clean"; sink(copy, clean) }
"#,
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        1,
        1,
        0,
        0,
        execute,
    )
}

pub fn with_php_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "php",
        Language::Php,
        "src/exact_flow.php",
        r#"
<?php
function relay(string $value): string { $relayed = $value; return $relayed; }
function sink(string $flowed, string $clean): void {}
function run(string $input): void { $copy = relay($input); $clean = "clean"; sink($copy, $clean); }
"#,
        ProcedureKind::Function,
        "relay($input)",
        "sink($copy, $clean)",
        "$relayed",
        "$copy",
        ExpectedSinkOutcome::NotReached,
        SemanticInputStatus::Unknown,
        true,
        1,
        1,
        0,
        0,
        execute,
    )
}

pub fn with_ruby_exact_helper<T>(execute: impl FnOnce(&ValueFlowConformanceCase<'_>) -> T) -> T {
    with_single_file_exact_helper(
        "ruby",
        Language::Ruby,
        "exact_flow.rb",
        r#"
def relay(value)
  relayed = value
  relayed
end
def sink(flowed, clean)
end
def run(input)
  copy = relay(input)
  clean = "clean"
  sink(copy, clean)
end
"#,
        ProcedureKind::Method,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        6,
        4,
        1,
        2,
        execute,
    )
}
