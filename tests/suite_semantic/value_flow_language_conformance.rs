#[path = "../common/value_flow_conformance.rs"]
mod value_flow_conformance;

use brokk_bifrost::Language;
use brokk_bifrost::analyzer::dataflow::{PathQuality, SemanticInputStatus};
use brokk_bifrost::analyzer::semantic::{IcfgEdgeKind, ProcedureKind, SemanticCapability};
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
    expected_carriers_for_calls(
        path,
        path,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
    )
}

fn expected_carriers_for_calls(
    run_path: &str,
    relay_path: &str,
    relay_call: &str,
    sink_call: &str,
    relay_local: &str,
    run_local: &str,
) -> Vec<CarrierMilestone> {
    vec![
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
            snippet: relay_local.into(),
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
            snippet: run_local.into(),
        },
        CarrierMilestone::SinkArgument {
            path: run_path.into(),
            caller: "run".into(),
            callee: "sink".into(),
            call: sink_call.into(),
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
            carriers,
            interprocedural: EXPECTED_INTERPROCEDURAL,
        },
    }]
}

#[allow(clippy::too_many_arguments)]
fn assert_multi_file_exact_helper_flow(
    name: &str,
    language: Language,
    files: &[InlineSourceFile<'_>],
    run_path: &str,
    relay_path: &str,
    procedure_kind: ProcedureKind,
    relay_call: &str,
    sink_call: &str,
    relay_local: &str,
    run_local: &str,
    flowed_outcome: ExpectedSinkOutcome,
    clean_outcome: ExpectedSinkOutcome,
    expected_discovery_status: SemanticInputStatus,
    expected_discovery_complete: bool,
    expected_result_complete: bool,
    meeting_count: usize,
) {
    let procedures = [
        ProcedureSelector {
            alias: "run",
            path: run_path,
            name: "run",
            kind: procedure_kind,
        },
        ProcedureSelector {
            alias: "relay",
            path: relay_path,
            name: "relay",
            kind: procedure_kind,
        },
        ProcedureSelector {
            alias: "sink",
            path: run_path,
            name: "sink",
            kind: procedure_kind,
        },
    ];
    let sinks = [
        CallArgumentSink {
            alias: "flowed",
            call: "sink_call",
            argument: 0,
            outcome: flowed_outcome,
        },
        CallArgumentSink {
            alias: "clean",
            call: "sink_call",
            argument: 1,
            outcome: clean_outcome,
        },
    ];
    let expected_carriers = expected_carriers_for_calls(
        run_path,
        relay_path,
        relay_call,
        sink_call,
        relay_local,
        run_local,
    );
    let expected_meetings = expected_meetings(&expected_carriers, meeting_count);
    assert_value_flow_conformance(&ValueFlowConformanceCase {
        name,
        language,
        files,
        procedures: &procedures,
        root: "run",
        calls: CALLS,
        source: ParameterSource {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete,
        expected_result_complete,
        expected_meetings: &expected_meetings,
    });
}

#[allow(clippy::too_many_arguments)]
fn assert_single_file_exact_helper_flow(
    name: &str,
    language: Language,
    path: &str,
    source: &str,
    procedure_kind: ProcedureKind,
    relay_call: &str,
    sink_call: &str,
    relay_local: &str,
    run_local: &str,
    flowed_outcome: ExpectedSinkOutcome,
    clean_outcome: ExpectedSinkOutcome,
    expected_discovery_status: SemanticInputStatus,
    expected_discovery_complete: bool,
    expected_result_complete: bool,
    meeting_count: usize,
) {
    let files = [InlineSourceFile { path, source }];
    assert_multi_file_exact_helper_flow(
        name,
        language,
        &files,
        path,
        path,
        procedure_kind,
        relay_call,
        sink_call,
        relay_local,
        run_local,
        flowed_outcome,
        clean_outcome,
        expected_discovery_status,
        expected_discovery_complete,
        expected_result_complete,
        meeting_count,
    );
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

#[test]
fn csharp_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::NotReached,
        SemanticInputStatus::Unknown,
        false,
        true,
        1,
    );
}

#[test]
fn javascript_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        6,
    );
}

#[test]
fn rust_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        1,
    );
}

#[test]
fn python_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unsupported {
            capability: SemanticCapability::ExceptionalControlFlow,
        },
        false,
        false,
        6,
    );
}

#[test]
fn php_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
        "php",
        Language::Php,
        "src/exact_flow.php",
        r#"
            <?php

            function relay(string $value): string {
                $relayed = $value;
                return $relayed;
            }

            function sink(string $flowed, string $clean): void {}

            function run(string $input): void {
                $copy = relay($input);
                $clean = "clean";
                sink($copy, $clean);
            }
        "#,
        ProcedureKind::Function,
        "relay($input)",
        "sink($copy, $clean)",
        "$relayed",
        "$copy",
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::NotReached,
        SemanticInputStatus::Unknown,
        false,
        true,
        1,
    );
}

#[test]
fn ruby_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        6,
    );
}

#[test]
fn scala_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        1,
    );
}

#[test]
fn kotlin_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
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
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::NotReached,
        SemanticInputStatus::Unknown,
        false,
        true,
        1,
    );
}

#[test]
#[ignore = "requires a proven complete witness across the C header declaration boundary"]
fn c_exact_helper_flow_through_header_declaration() {
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
    assert_multi_file_exact_helper_flow(
        "c",
        Language::Cpp,
        &files,
        "c/conformance/caller.c",
        "c/conformance/exact_flow.c",
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        2,
    );
}

#[test]
#[ignore = "requires a proven complete witness across the C++ header declaration boundary"]
fn cpp_exact_helper_flow_through_header_declaration() {
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
    assert_multi_file_exact_helper_flow(
        "cpp",
        Language::Cpp,
        &files,
        "cpp/conformance/caller.cpp",
        "cpp/conformance/exact_flow.cpp",
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        2,
    );
}

#[test]
fn go_exact_helper_flow() {
    assert_single_file_exact_helper_flow(
        "go",
        Language::Go,
        "exact_flow.go",
        r#"
            package conformance

            func relay(value string) string {
                relayed := value
                return relayed
            }

            func sink(flowed string, clean string) {}

            func run(input string) {
                copy := relay(input)
                clean := "clean"
                sink(copy, clean)
            }
        "#,
        ProcedureKind::Function,
        "relay(input)",
        "sink(copy, clean)",
        "relayed",
        "copy",
        ExpectedSinkOutcome::Reached,
        ExpectedSinkOutcome::Inconclusive,
        SemanticInputStatus::Unknown,
        false,
        false,
        1,
    );
}
