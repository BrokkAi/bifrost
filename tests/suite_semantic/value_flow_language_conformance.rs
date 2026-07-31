use brokk_bifrost::Language;
use brokk_bifrost::analyzer::dataflow::{PathQuality, SemanticInputStatus};
use brokk_bifrost::analyzer::semantic::{IcfgEdgeKind, ProcedureKind, SemanticCapability};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowMayStatus, ValueFlowMustStatus, ValueFlowPortKey,
};

use crate::value_flow_conformance::{
    CallArgumentSink, CallSelector, CarrierMilestone, ExpectedMeeting, ExpectedSinkOutcome,
    ExpectedWitness, InlineSourceFile, InterproceduralMilestone, ParameterSource,
    ProcedureSelector, ValueFlowConformanceCase, assert_value_flow_conformance,
};
use crate::value_flow_scenarios::{
    with_java_ambiguous_call_negative, with_java_branch_merge, with_java_capture_flow,
    with_java_cleanup_flow, with_java_early_return, with_java_exact_helper,
    with_java_exceptional_flow, with_java_field_access_flow, with_java_field_alias_flow,
    with_java_loop_exit, with_java_receiver_flow, with_java_two_matched_calls,
    with_java_unresolved_call_negative, with_typescript_ambiguous_call_negative,
    with_typescript_branch_merge, with_typescript_capture_flow, with_typescript_cleanup_flow,
    with_typescript_early_return, with_typescript_exact_helper, with_typescript_exceptional_flow,
    with_typescript_field_access_flow, with_typescript_field_alias_flow, with_typescript_loop_exit,
    with_typescript_receiver_flow, with_typescript_two_matched_calls,
    with_typescript_unresolved_call_negative,
};

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
        public_endpoint_count: meeting_count,
        may_status: ValueFlowMayStatus::Proven,
        public_may_complete_count: 0,
        public_may_partial_count: 0,
        must_status: ValueFlowMustStatus::NotEstablished,
        uncertain: false,
        path_qualities: EXPECTED_PATH_QUALITIES,
        witness: ExpectedWitness {
            truncated: false,
            may_status: ValueFlowMayStatus::Proven,
            path_quality: PathQuality::PROVEN_COMPLETE,
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
        unmodeled_call_behavior: brokk_bifrost::analyzer::dataflow::UnmodeledCallBehavior::Paranoid,
        source: ParameterSource::Parameter {
            procedure: "run",
            ordinal: 0,
        },
        sinks: &sinks,
        expected_discovery_status,
        expected_discovery_complete,
        expected_result_complete,
        expected_public_ambiguous: false,
        expected_location_relations: &[],
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
    with_java_exact_helper(assert_value_flow_conformance);
}

#[test]
fn typescript_exact_helper_flow() {
    with_typescript_exact_helper(assert_value_flow_conformance);
}

#[test]
fn java_branch_merge_flow() {
    with_java_branch_merge(assert_value_flow_conformance);
}

#[test]
fn typescript_branch_merge_flow() {
    with_typescript_branch_merge(assert_value_flow_conformance);
}

#[test]
fn java_loop_exit_flow() {
    with_java_loop_exit(assert_value_flow_conformance);
}

#[test]
fn typescript_loop_exit_flow() {
    with_typescript_loop_exit(assert_value_flow_conformance);
}

#[test]
fn java_early_return_excludes_unreachable_sink() {
    with_java_early_return(assert_value_flow_conformance);
}

#[test]
fn typescript_early_return_excludes_unreachable_sink() {
    with_typescript_early_return(assert_value_flow_conformance);
}

#[test]
fn java_two_call_sites_match_returns() {
    with_java_two_matched_calls(assert_value_flow_conformance);
}

#[test]
fn typescript_two_call_sites_match_returns() {
    with_typescript_two_matched_calls(assert_value_flow_conformance);
}

#[test]
fn java_receiver_flows_through_callee_receiver_port() {
    with_java_receiver_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_receiver_flows_through_callee_receiver_port() {
    with_typescript_receiver_flow(assert_value_flow_conformance);
}

#[test]
fn java_exceptional_completion_is_an_inconclusive_negative() {
    with_java_exceptional_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_exceptional_completion_reaches_catch_sink() {
    with_typescript_exceptional_flow(assert_value_flow_conformance);
}

#[test]
fn java_cleanup_flow_is_an_inconclusive_negative() {
    with_java_cleanup_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_cleanup_flow_is_an_inconclusive_negative() {
    with_typescript_cleanup_flow(assert_value_flow_conformance);
}

#[test]
fn java_unresolved_capture_invocation_is_an_inconclusive_negative() {
    with_java_capture_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_unresolved_capture_invocation_is_an_inconclusive_negative() {
    with_typescript_capture_flow(assert_value_flow_conformance);
}

#[test]
fn java_field_store_load_preserves_bounded_access_path() {
    with_java_field_access_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_field_store_load_preserves_bounded_access_path() {
    with_typescript_field_access_flow(assert_value_flow_conformance);
}

#[test]
fn java_alias_field_flow_is_an_inconclusive_negative() {
    with_java_field_alias_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_alias_field_flow_is_an_inconclusive_negative() {
    with_typescript_field_alias_flow(assert_value_flow_conformance);
}

#[test]
fn java_unresolved_call_result_is_an_inconclusive_negative() {
    with_java_unresolved_call_negative(assert_value_flow_conformance);
}

#[test]
fn typescript_unresolved_call_result_is_an_inconclusive_negative() {
    with_typescript_unresolved_call_negative(assert_value_flow_conformance);
}

#[test]
fn java_ambiguous_call_does_not_invent_a_meeting() {
    with_java_ambiguous_call_negative(assert_value_flow_conformance);
}

#[test]
fn typescript_ambiguous_call_does_not_invent_a_meeting() {
    with_typescript_ambiguous_call_negative(assert_value_flow_conformance);
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
        1,
    );
}

#[test]
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
        1,
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
