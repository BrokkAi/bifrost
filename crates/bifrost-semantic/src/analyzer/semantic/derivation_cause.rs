/// Operational causes carried by producer-owned derivation reason values.
/// These labels describe outcomes, never source syntax or rendered messages.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DerivationExecutionCause {
    Cancelled,
    Budget,
    Snapshot,
    Provider,
}

impl DerivationExecutionCause {
    /// Unknown labels are operational until their producer's cause is audited.
    pub fn from_reason(reason: &str) -> Option<Self> {
        reason::classify_known(reason).unwrap_or(Some(Self::Provider))
    }

    pub fn from_cfg_error<Node: std::fmt::Debug>(
        error: &crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError<Node>,
    ) -> Self {
        use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;
        match error {
            CfgAlgorithmError::Cancelled { .. } => Self::Cancelled,
            CfgAlgorithmError::ExceededBudget(_) => Self::Budget,
            CfgAlgorithmError::InvalidNode(node) => {
                panic!("validated procedure has invalid CFG point {node:?}")
            }
        }
    }
}

/// Producer-owned labels. One table also generates the regression inventory.
pub mod reason {
    use super::DerivationExecutionCause;
    macro_rules! reasons {
        ($($name:ident = $label:expr => $cause:expr),* $(,)?) => {
            $(pub const $name: &str = $label;)*
            pub fn classify_known(label: &str) -> Option<Option<DerivationExecutionCause>> {
                match label {
                    $($name => Some($cause),)*
                    _ => None,
                }
            }
            #[cfg(test)]
            const ALL: &[(&str, Option<DerivationExecutionCause>)] = &[$(($name, $cause)),*];
        };
    }
    // Legacy wrappers outside statement reachability still fail closed. Their
    // typed producers must carry causes rather than classify this label.
    pub const QUERY_INCOMPLETE: &str = "query_incomplete";

    reasons! {
        JAVA_CALLER_PUBLIC_IDENTITY_MISSING = "java_caller_public_identity_missing" => Some(DerivationExecutionCause::Provider),
        JAVA_REFERENCE_EXECUTION_CONTEXT_UNKNOWN = "java_reference_execution_context_unknown" => None,
        JAVA_REFERENCE_EXECUTION_CONTEXT_CAPABILITY_ABSENT = "java_reference_execution_context_capability_absent" => Some(DerivationExecutionCause::Provider),
        JAVA_REFERENCE_EXECUTION_CONTEXT_ROW_ABSENT = "java_reference_execution_context_row_absent" => Some(DerivationExecutionCause::Snapshot),
        JAVA_REFERENCE_EXECUTION_CONTEXT_CORRUPT = "java_reference_execution_context_corrupt" => Some(DerivationExecutionCause::Provider),
        RUST_COPY_CENSUS_MISSING = "rust_copy.census_missing" => None,
        RUST_COPY_CENSUS_CORRUPT = "rust_copy.census_corrupt" => None,
        RUST_COPY_BOUNDARY_MACRO = "rust_copy.boundary_macro" => None,
        RUST_COPY_BOUNDARY_DERIVE = "rust_copy.boundary_derive" => None,
        RUST_COPY_BOUNDARY_EXPANDING_ATTRIBUTE = "rust_copy.boundary_expanding_attribute" => None,
        RUST_COPY_BOUNDARY_INTERNAL_ATTRIBUTE = "rust_copy.boundary_internal_attribute" => None,
        RUST_COPY_BOUNDARY_SYNTAX_ERROR = "rust_copy.boundary_syntax_error" => None,
        RUST_COPY_MODULE_UNIVERSE_OPEN = "rust_copy.module_universe_open" => None,
        RUST_COPY_UNRESOLVED_SUBJECT = "rust_copy.unresolved_subject" => None,
        RUST_COPY_ALIAS_SUBJECT = "rust_copy.alias_subject" => None,
        RUST_COPY_UNPAIRED_IMPL = "rust_copy.unpaired_impl" => None,
        RUST_COPY_MATCHING_TRAIT_IMPL = "rust_copy.matching_trait_impl" => None,
        RUST_COPY_PUBLICATION_INCOMPLETE = "rust_copy.publication_incomplete" => None,
        RUST_COPY_TARGET_UNAVAILABLE = "rust_copy.target_unavailable" => Some(DerivationExecutionCause::Provider),
        JVM_INDEX_CAPPED_ENTRIES = "jvm.index.capped_entries" => None,
        ARTIFACT_MEMBERS_LIMIT = "limit.artifact_members" => None,
        KOTLIN_CLASSIFICATION_CAPPED = "kotlin.classification_capped" => None,
        KOTLIN_CLASSIFICATION_MALFORMED = "kotlin.classification_malformed" => None,
        PREPROCESSING_PRESENT = "preprocessing_present" => None,
        MACRO_POSSIBLE = "macro_possible" => None,
        CPP_ANALYZER_UNAVAILABLE = "cpp_analyzer_unavailable" => Some(DerivationExecutionCause::Provider),
        NOT_CPP = "not_cpp" => None,
        ANCHOR_SYNTAX_MISSING = "anchor_syntax_missing" => None,
        RETURN_SEMANTICS_MISSING = "return_semantics_missing" => None,
        ASSIGNMENT_SEMANTICS_MISSING = "assignment_semantics_missing" => None,
        RESOLVED_CALL_IDENTITY_UNAVAILABLE = "resolved_call_identity_unavailable" => None,
        CALL_FUNCTION_MISSING = "call_function_missing" => None,
        RESOLVED_CALL_NAME_MISSING = "resolved_call_name_missing" => None,
        RESOLVED_CALL_IDENTITY_MISMATCH = "resolved_call_identity_mismatch" => None,
        CALL_SEMANTICS_MISSING = "call_semantics_missing" => None,
        RESOLVED_CALL_HEADER_OWNER_MISSING = "resolved_call_header_owner_missing" => None,
        CALL_ARGUMENTS_MISSING = "call_arguments_missing" => None,
        CALL_ARGUMENT_MISSING = "call_argument_missing" => None,
        CALL_ARGUMENT_UNREADABLE = "call_argument_unreadable" => None,
        CALL_ARGUMENT_ALIAS_UNKNOWN = "call_argument_alias_unknown" => None,
        // An external boundary depends on the selected external inventory, which
        // is neither a unit-key dimension nor a ledgered read yet. Promote these
        // reasons to content only when #7633 (and its per-language siblings) ledger it.
        // Selected C# configuration is neither a demonstrated unit-key dimension
        // nor a ledgered read, so compilation disagreement is operational.
        CSHARP_COMPILATION_ACCESS_UNKNOWN = "csharp-compilation-access-unknown" => Some(DerivationExecutionCause::Provider),
        // The unmodeled tier includes compilation-wide usings, whose selected
        // extent is not yet ledgered. Preserve provider uncertainty.
        CSHARP_COMPILATION_USINGS_INCOMPLETE = "csharp_compilation_usings_incomplete" => Some(DerivationExecutionCause::Provider),
        CSHARP_CONDITIONAL_BRANCH_UNSEEN = "csharp_conditional_branch_unseen" => None,
        CSHARP_MEMBER_ACCESS_UNMODELED = "csharp_member_access_unmodeled" => Some(DerivationExecutionCause::Provider),
        CSHARP_SOURCE_ANCHOR_UNMODELED = "csharp_source_anchor_unmodeled" => Some(DerivationExecutionCause::Provider),
        CSHARP_SOURCE_IMPORT_UNMODELED = "csharp_source_import_unmodeled" => Some(DerivationExecutionCause::Provider),
        PYTHON_BINDING_ROWS_MISSING = "python_binding_rows_missing" => Some(DerivationExecutionCause::Provider),
        PYTHON_BINDING_FORMAT_STALE = "python_binding_format_stale" => Some(DerivationExecutionCause::Provider),
        CSHARP_ALIAS_CYCLE = "csharp_alias_cycle" => Some(DerivationExecutionCause::Provider),
        CSHARP_EXTERNAL_UNINDEXED = "csharp_external_unindexed" => Some(DerivationExecutionCause::Provider),
        CSHARP_INHERITED_TYPES_UNMODELED = "csharp_inherited_types_unmodeled" => Some(DerivationExecutionCause::Provider),
        CSHARP_METHOD_APPLICABILITY_UNMODELED = "csharp_method_applicability_unmodeled" => Some(DerivationExecutionCause::Provider),
        OPEN_BOUNDARY = "OpenBoundary" => Some(DerivationExecutionCause::Provider),
        JVM_UNIT_PACKAGE_UNKNOWN = "jvm-unit-package-unknown" => Some(DerivationExecutionCause::Provider),
        JVM_PACKAGE_PROVIDER_PARTIAL = "jvm-package-provider-partial" => Some(DerivationExecutionCause::Provider),
        JVM_PACKAGE_PROVIDER_UNACQUIRED = "jvm-package-provider-unacquired" => Some(DerivationExecutionCause::Provider),
        JVM_EXPRESSION_PREFIX_UNPROVEN = "jvm-expression-prefix-unproven" => None,
        EXTERNAL_DECLARED_UNINDEXED = "external_declared_unindexed" => Some(DerivationExecutionCause::Provider),
        // A Go import is incomplete when its package rows are missing or
        // unconfirmed, which also depends on the selected external inventory.
        GO_IMPORT_INCOMPLETE = "go-import-incomplete" => Some(DerivationExecutionCause::Provider),
        GO_EXTERNAL_MEMBER_UNPROVIDED = "go-external-member-unprovided" => Some(DerivationExecutionCause::Provider),
        OWNER_INVENTORY_OPEN = "OwnerInventoryOpen" => Some(DerivationExecutionCause::Provider),
        // A missing nominal member can depend on a selected provider surface.
        // Retain the operational barrier until its absence has a ledgered input.
        // #7979: workspace class decorators retain candidates without member-preservation proof.
        PYTHON_MODEL_ALLOCATOR_RESULT_UNKNOWN = "python_model_allocator_result_unknown" => Some(DerivationExecutionCause::Provider),
        PYTHON_MODEL_MEMBER_INVENTORY_OPEN = "python_model_member_inventory_open" => Some(DerivationExecutionCause::Provider),
        PYTHON_MODEL_DESCRIPTOR_ROLE_UNKNOWN = "python_model_descriptor_role_unknown" => Some(DerivationExecutionCause::Provider),
        PYTHON_SOURCE_IMPLICIT_PROTOCOL_OPEN = "python_source_implicit_protocol_open" => Some(DerivationExecutionCause::Provider),
        PYTHON_CLASS_DECORATOR_UNPROVEN = "python_class_decorator_unproven" => Some(DerivationExecutionCause::Provider),
        PYTHON_RECEIVER_SUBCLASS_MEMBER_MISSING = "python_receiver_subclass_member_missing" => Some(DerivationExecutionCause::Provider),
        UNACQUIRED_OBJECT_MEMBER = "UnacquiredObjectMember" => Some(DerivationExecutionCause::Provider),
        HIERARCHY_INCOMPLETE = "hierarchy_incomplete" => None,
        HIERARCHY_AMBIGUOUS = "hierarchy_ambiguous" => None,
        COVERAGE_INCOMPLETE = "coverage_incomplete" => None,
        PROVIDER_UNAVAILABLE = "provider_unavailable" => Some(DerivationExecutionCause::Provider),
        FORWARD_SATISFACTION_INCOMPLETE = "forward_satisfaction_incomplete" => None,
        GO_ALIAS_TERMINAL_INCOMPLETE = "alias target has no complete selected terminal" => None,
        // These explicit registrations preserve the prior unknown-label fallback.
        JVM_IMPORT_SELECTOR_OPEN = "jvm-import-selector-open" => Some(DerivationExecutionCause::Provider),
        JVM_IMPORT_OWNER_OPEN = "jvm-import-owner-open" => Some(DerivationExecutionCause::Provider),
        SCALA_PACKAGE_CLAUSE_BOUNDARY_OPEN = "scala-package-clause-boundary-open" => Some(DerivationExecutionCause::Provider),
        JVM_SOURCE_DOMAIN_OPEN = "jvm-source-domain-open" => Some(DerivationExecutionCause::Provider),
        JVM_PACKAGE_ALIAS_ROUTE_OPEN = "jvm-package-alias-route-open" => Some(DerivationExecutionCause::Provider),
        JVM_PACK_PACKAGE_MEMBER = "jvm-pack-package-member" => Some(DerivationExecutionCause::Provider),
        JVM_PACK_PACKAGE_MEMBER_OPEN = "JvmPackPackageMemberOpen" => Some(DerivationExecutionCause::Provider),
        AMBIGUOUS_MEMBER = "ambiguous_member" => None,
        AMBIGUOUS_PROCEDURE = "ambiguous_procedure" => None,
        AMBIGUOUS_STATEMENT_SPAN = "ambiguous_statement_span" => None,
        ASSESSMENT_INCOMPLETE = "assessment_incomplete" => Some(DerivationExecutionCause::Provider),
        BODY_FIELD_MISSING = "body_field_missing" => None,
        CANCELLED = crate::analyzer::semantic::statement_entries::reason::CANCELLED => Some(DerivationExecutionCause::Cancelled),
        CAUGHT_TYPE_UNRESOLVED = "caught_type_unresolved" => None,
        CLEANUP_KIND_UNRECOGNIZED = "cleanup_kind_unrecognized" => None,
        CLEANUP_OUTCOME_UNPROVEN = "cleanup_outcome_unproven" => None,
        CLEANUP_SEMANTICS_UNPUBLISHED = "cleanup_semantics_unpublished" => None,
        CLEANUP_SOURCE_MAPPING_MISSING = "cleanup_source_mapping_missing" => None,
        FIXED_LIMIT = "fixed_limit" => None,
        COMPARISON_BUDGET = "comparison_budget" => Some(DerivationExecutionCause::Budget),
        CONDITION_FIELD_MISSING = "condition_field_missing" => None,
        CONTROL_BUDGET_EXHAUSTED = crate::analyzer::semantic::statement_entries::reason::CONTROL_BUDGET_EXHAUSTED => Some(DerivationExecutionCause::Budget),
        CONTROL_EVIDENCE_INCOMPLETE = crate::analyzer::semantic::statement_entries::reason::CONTROL_EVIDENCE_INCOMPLETE => None,
        CONTROL_FRONTIER_INCOMPLETE = crate::analyzer::semantic::statement_entries::reason::CONTROL_FRONTIER_INCOMPLETE => None,
        DEFERRED_BODY = "deferred_body" => None,
        EFFECTFUL_BODY = "effectful_body" => None,
        EFFECTFUL_CONDITION = "effectful_condition" => None,
        HANDLER_IDENTITY_UNPROVEN = "handler_identity_unproven" => None,
        LEXICAL_BINDING_UNAVAILABLE = "lexical_binding_unavailable" => None,
        LEXICAL_ENVIRONMENT_INCOMPLETE = "lexical_environment_incomplete" => None,
        MEMBER_RESOLUTION_UNAVAILABLE = "member_resolution_unavailable" => None,
        MISSING_BODY = "missing_body" => None,
        MISSING_BRANCH_FIELD = "missing_branch_field" => None,
        MISSING_STATEMENT_ENTRY = "missing_statement_entry" => None,
        MISSING_TRY_BODY = "missing_try_body" => None,
        NO_ENCLOSING_PROCEDURE = "no_enclosing_procedure" => None,
        NON_LOCAL_REFERENCE = "non_local_reference" => None,
        PARTIAL_PROCEDURE = "partial_procedure" => None,
        PARTIAL_PRODUCER = "partial_producer" => None,
        PENDING_CLEANUP_STATE_BUDGET_EXHAUSTED = "pending_cleanup_state_budget_exhausted" => Some(DerivationExecutionCause::Budget),
        PREPARED_SYNTAX_UNAVAILABLE = "prepared_syntax_unavailable" => Some(DerivationExecutionCause::Provider),
        PROCEDURE_MAPPING_INEXACT = "procedure_mapping_inexact" => None,
        PROCEDURE_MAPPING_MISSING = "procedure_mapping_missing" => None,
        PROCEDURE_SEMANTIC_QUALITY_INCOMPLETE = "procedure_semantic_quality_incomplete" => None,
        PROCEDURE_SYNTAX_AMBIGUOUS = "procedure_syntax_ambiguous" => None,
        PROCEDURE_SYNTAX_INEXACT = "procedure_syntax_inexact" => None,
        PROCEDURE_SYNTAX_MISSING = "procedure_syntax_missing" => None,
        PROCEDURE_SYNTAX_RECOVERY = "procedure_syntax_recovery" => None,
        METHOD_OVERRIDE_LIMIT = "method_override_limit" => Some(DerivationExecutionCause::Budget),
        METHOD_OVERRIDE_INCOMPLETE = "method_override_incomplete" => Some(DerivationExecutionCause::Provider),
        SNAPSHOT_MISMATCH = "snapshot_mismatch" => Some(DerivationExecutionCause::Snapshot),
        SOURCE_BUDGET_EXHAUSTED = "source_budget_exhausted" => Some(DerivationExecutionCause::Budget),
        SOURCE_IDENTITY_MISMATCH = "source_identity_mismatch" => Some(DerivationExecutionCause::Snapshot),
        SOURCE_LIMIT = "source_limit" => Some(DerivationExecutionCause::Budget),
        STALE_SOURCE = "stale_source" => Some(DerivationExecutionCause::Snapshot),
        SYNTAX_RECOVERY = "syntax_recovery" => None,
        SYNTAX_UNAVAILABLE = "syntax_unavailable" => Some(DerivationExecutionCause::Provider),
        TARGET_RECEIVER_READ_UNAVAILABLE = "target_receiver_read_unavailable" => Some(DerivationExecutionCause::Provider),
        UNKNOWN = "unknown" => Some(DerivationExecutionCause::Provider),
        TYPESTATE_UNPROVEN_HANDOFF = "typestate-unproven-handoff" => None,
        TYPESTATE_UNPROVEN_GUARD = "typestate-unproven-guard" => None,
        UNPROVEN_ACTIVATION = "unproven_activation" => None,
        UNSUPPORTED_CALLABLE_KIND = "unsupported_callable_kind" => None,
        UNSUPPORTED_CASE_FACT = "unsupported_case_fact" => None,
        UNSUPPORTED_CONDITION = "unsupported_condition" => None,
        UNSUPPORTED_LANGUAGE = "unsupported_language" => None,
        UNSUPPORTED_RELATION = "unsupported_relation" => None,
        WORK_LIMIT = "work_limit" => Some(DerivationExecutionCause::Budget),
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7278: unrecognized operational reason labels defaulted to content"
    )]
    fn every_registered_reason_constant_is_classified_and_unknowns_fail_closed() {
        // This inventories declared constants, not arbitrary future literals
        // outside the table. Producer regressions must also exercise their
        // emitted reasons, since their public result fields remain strings.
        for &(label, expected) in ALL {
            assert_eq!(classify_known(label), Some(expected), "{label}");
            assert_eq!(
                DerivationExecutionCause::from_reason(label),
                expected,
                "{label}"
            );
        }
        for label in [
            JVM_IMPORT_SELECTOR_OPEN,
            JVM_IMPORT_OWNER_OPEN,
            QUERY_INCOMPLETE,
        ] {
            if label != QUERY_INCOMPLETE {
                assert_eq!(
                    classify_known(label),
                    Some(Some(DerivationExecutionCause::Provider))
                );
            }
            assert_eq!(
                DerivationExecutionCause::from_reason(label),
                DerivationExecutionCause::from_reason("future_execution_stop")
            );
        }
        assert_eq!(
            DerivationExecutionCause::from_reason("future_execution_stop"),
            Some(DerivationExecutionCause::Provider)
        );
    }
}
