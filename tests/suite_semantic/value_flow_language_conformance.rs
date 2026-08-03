use crate::value_flow_conformance::assert_value_flow_conformance;
use crate::value_flow_scenarios::{
    with_c_exact_helper, with_cpp_exact_helper, with_csharp_exact_helper, with_go_exact_helper,
    with_java_ambiguous_call_negative, with_java_branch_merge, with_java_capture_flow,
    with_java_cleanup_flow, with_java_early_return, with_java_exact_helper,
    with_java_exceptional_flow, with_java_field_access_flow, with_java_field_alias_flow,
    with_java_index_access_flow, with_java_loop_exit, with_java_over_bound_field_flow,
    with_java_receiver_flow, with_java_split_exact_helper, with_java_two_matched_calls,
    with_java_unresolved_call_negative, with_javascript_exact_helper, with_kotlin_exact_helper,
    with_php_exact_helper, with_python_exact_helper, with_ruby_exact_helper,
    with_rust_exact_helper, with_scala_exact_helper, with_typescript_ambiguous_call_negative,
    with_typescript_branch_merge, with_typescript_capture_flow, with_typescript_cleanup_flow,
    with_typescript_early_return, with_typescript_exact_helper, with_typescript_exceptional_flow,
    with_typescript_field_access_flow, with_typescript_field_alias_flow,
    with_typescript_index_access_flow, with_typescript_loop_exit,
    with_typescript_over_bound_field_flow, with_typescript_receiver_flow,
    with_typescript_two_matched_calls, with_typescript_unresolved_call_negative,
};

#[test]
fn java_exact_helper_flow() {
    with_java_exact_helper(assert_value_flow_conformance);
}

#[test]
fn java_split_file_exact_helper_flow() {
    with_java_split_exact_helper(assert_value_flow_conformance);
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
fn java_exact_indices_remain_distinct_in_memory_relations() {
    with_java_index_access_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_exact_indices_remain_distinct_in_memory_relations() {
    with_typescript_index_access_flow(assert_value_flow_conformance);
}

#[test]
fn java_over_bound_access_path_is_an_explicit_summary() {
    with_java_over_bound_field_flow(assert_value_flow_conformance);
}

#[test]
fn typescript_over_bound_access_path_is_an_explicit_summary() {
    with_typescript_over_bound_field_flow(assert_value_flow_conformance);
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
    with_csharp_exact_helper(assert_value_flow_conformance);
}

#[test]
fn javascript_exact_helper_flow() {
    with_javascript_exact_helper(assert_value_flow_conformance);
}

#[test]
fn rust_exact_helper_flow() {
    with_rust_exact_helper(assert_value_flow_conformance);
}

#[test]
fn python_exact_helper_flow() {
    with_python_exact_helper(assert_value_flow_conformance);
}

#[test]
fn php_exact_helper_flow() {
    with_php_exact_helper(assert_value_flow_conformance);
}

#[test]
fn ruby_exact_helper_flow() {
    with_ruby_exact_helper(assert_value_flow_conformance);
}

#[test]
fn scala_exact_helper_flow() {
    with_scala_exact_helper(assert_value_flow_conformance);
}

#[test]
fn kotlin_exact_helper_flow() {
    with_kotlin_exact_helper(assert_value_flow_conformance);
}

#[test]
fn c_exact_helper_flow_through_header_declaration() {
    with_c_exact_helper(assert_value_flow_conformance);
}

#[test]
fn cpp_exact_helper_flow_through_header_declaration() {
    with_cpp_exact_helper(assert_value_flow_conformance);
}

#[test]
fn go_exact_helper_flow() {
    with_go_exact_helper(assert_value_flow_conformance);
}
