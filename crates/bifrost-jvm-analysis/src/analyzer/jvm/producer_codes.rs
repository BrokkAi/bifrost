//! Diagnostic stability for JVM external-index producers.

use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
use brokk_bifrost_analysis::analyzer::semantic_model::ProducerDiagnostic;

#[derive(Clone, Copy)]
pub(crate) enum CodeClass {
    Gap,
    Artifact,
    Provider,
    Budget,
    Fallback,
}

#[derive(Clone, Copy)]
pub(crate) struct JvmProducerCode {
    pub code: &'static str,
    class: CodeClass,
}

macro_rules! codes {
    ($($name:ident = $code:literal => $class:ident,)+) => {
        $(pub(crate) const $name: JvmProducerCode = JvmProducerCode {
            code: $code,
            class: CodeClass::$class,
        };)+
        fn class_of(code: &str) -> Option<CodeClass> {
            match code {
                $($code => Some($name.class),)+
                _ => None,
            }
        }
    };
}

codes! {
    JVM_INVENTORY_SEALED = "jvm.inventory.sealed" => Artifact,
    JAVA_ARCHIVE_ENTRY = "java.archive.entry" => Gap,
    JAVA_ARCHIVE_ENTRY_NAME = "java.archive.entry_name" => Gap,
    JAVA_ARCHIVE_ENTRY_READ = "java.archive.entry_read" => Gap,
    JAVA_ARCHIVE_INVALID = "java.archive.invalid" => Artifact,
    JAVA_ARCHIVE_NO_EXTERNAL_DECLARATIONS = "java.archive.no_external_declarations" => Artifact,
    JAVA_CLASS_INVALID = "java.class.invalid" => Artifact,
    JAVA_CLASS_UNSUPPORTED_FIELD_SIGNATURE = "java.class.unsupported_field_signature" => Gap,
    JAVA_CLASS_UNSUPPORTED_METHOD_NAME = "java.class.unsupported_method_name" => Gap,
    JAVA_CLASS_UNSUPPORTED_METHOD_SIGNATURE = "java.class.unsupported_method_signature" => Gap,
    JAVA_CLASS_UNSUPPORTED_SIGNATURE = "java.class.unsupported_signature" => Gap,
    JAVA_SOURCE_ENCODING = "java.source.encoding" => Gap,
    JAVA_SOURCE_PARSE = "java.source.parse" => Gap,
    JAVA_SOURCE_UNSUPPORTED_FIELD_TYPE = "java.source.unsupported_field_type" => Gap,
    JAVA_SOURCE_UNSUPPORTED_HIERARCHY_TYPE = "java.source.unsupported_hierarchy_type" => Gap,
    JAVA_SOURCE_UNSUPPORTED_PARAMETER_TYPE = "java.source.unsupported_parameter_type" => Gap,
    JAVA_SOURCE_UNSUPPORTED_RETURN_TYPE = "java.source.unsupported_return_type" => Gap,
    JAVA_SOURCE_BINARY_CONFLICT = "java.source_binary_conflict" => Artifact,
    AUXILIARY_SOURCE_DIAGNOSTICS = "java.source.auxiliary_diagnostics" => Gap,
    SCALA_ARCHIVE_ENTRY = "scala.archive.entry" => Gap,
    SCALA_ARCHIVE_ENTRY_NAME = "scala.archive.entry_name" => Gap,
    SCALA_ARCHIVE_ENTRY_READ = "scala.archive.entry_read" => Gap,
    SCALA_ARCHIVE_INVALID = "scala.archive.invalid" => Artifact,
    SCALA_ARCHIVE_NO_EXTERNAL_DECLARATIONS = "scala.archive.no_external_declarations" => Artifact,
    SCALA_SIGNATURE_REPEATED_PARAMETER_LIST = "scala.signature.repeated_parameter_list" => Gap,
    SCALA_SOURCE_ENCODING = "scala.source.encoding" => Gap,
    SCALA_SOURCE_PARSE = "scala.source.parse" => Gap,
    LIMIT_LOCATOR_PATH = "limit.locator_path" => Gap,
    LIMIT_ARCHIVE_DIRECTORY = "limit.archive_directory" => Gap,
    LIMIT_ARCHIVE_ENTRIES = "limit.archive_entries" => Gap,
    JVM_DEPENDENCY_UNRESOLVED = "jvm.dependency_unresolved" => Artifact,
    JVM_DEPENDENCY_UNAVAILABLE = "jvm.dependency_unavailable" => Provider,
    JVM_DISCOVERY_SUPPRESSED = "jvm.discovery.suppressed" => Provider,
    JVM_INDEX_BUDGET = "jvm.index.runtime_budget" => Budget,
    JVM_INDEX_CAPPED_ENTRIES = "jvm.index.capped_entries" => Artifact,
    LIMIT_ARTIFACT_MEMBERS = "limit.artifact_members" => Artifact,
    KOTLIN_CLASSIFICATION_CAPPED = "kotlin.classification_capped" => Artifact,
    KOTLIN_CLASSIFICATION_MALFORMED = "kotlin.classification_malformed" => Artifact,
    JDK_HOME_UNAVAILABLE = "jdk.home.unavailable" => Artifact,
    JVM_INDEX_UNREAD_ENTRIES = "jvm.index.unread_entries" => Fallback,
    JDK_HOME_INVALID = "jdk.home.invalid" => Fallback,
    KOTLIN_CLASSIFICATION_INCOMPLETE = "kotlin.classification_incomplete" => Fallback,
    LIMIT_DEPENDENCIES = "limit.dependencies" => Fallback,
    LIMIT_RECORDS = "limit.records" => Fallback,
    JDK_JMODS_INVALID = "jdk.jmods.invalid" => Fallback,
    ARTIFACT_KIND = "artifact.kind" => Fallback,
    ARTIFACT_ROLE = "artifact.role" => Fallback,
}

pub(crate) fn classify(diagnostic: &ProducerDiagnostic) -> QueryReadIncomplete {
    let detail = || {
        brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
            format_args!("{}: {}", diagnostic.code, diagnostic.message),
            // Called only for this module's finite, recognized code vocabulary.
            format_args!(
                "JVM external index diagnostic {}; detail_kind=ProducerDiagnostic",
                diagnostic.code
            ),
            std::iter::once((&diagnostic.code, &diagnostic.message)),
        )
        .into_boxed_str()
    };
    match class_of(&diagnostic.code) {
        Some(CodeClass::Gap) => QueryReadIncomplete::SemanticEvidenceGap(detail()),
        Some(CodeClass::Artifact) => QueryReadIncomplete::ArtifactUnavailable(detail()),
        Some(CodeClass::Budget) => QueryReadIncomplete::ProofStopped {
            reason: "jvm_index_runtime_budget",
            cause: Some(
                brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Budget,
            ),
        },
        Some(CodeClass::Provider) => QueryReadIncomplete::SemanticEvidenceUnavailable(detail()),
        Some(CodeClass::Fallback) | None => {
            brokk_bifrost_analysis::analyzer::common::external_index_incompleteness(diagnostic)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;
    use brokk_bifrost_analysis::analyzer::semantic_model::ProducerDiagnosticSeverity;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12527: external-index diagnostic prose overflowed policy adaptation"
    )]
    fn oversized_external_prose_remains_typed_and_bounded() {
        for code in [
            JAVA_SOURCE_PARSE,
            JVM_DEPENDENCY_UNRESOLVED,
            JVM_DEPENDENCY_UNAVAILABLE,
        ] {
            let fitting = ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Warning,
                code: code.code.into(),
                location: None,
                source_entry: None,
                declaration: None,
                message: "fits".into(),
            };
            let gap = classify(&fitting);
            let text = match &gap {
                QueryReadIncomplete::SemanticEvidenceGap(x)
                | QueryReadIncomplete::ArtifactUnavailable(x)
                | QueryReadIncomplete::SemanticEvidenceUnavailable(x) => x,
                _ => panic!("text producer"),
            };
            assert_eq!(text.as_ref(), format!("{}: fits", code.code));
            let huge = ProducerDiagnostic {
                message: "x".repeat(10_000),
                ..fitting
            };
            let bounded = classify(&huge);
            assert_eq!(
                std::mem::discriminant(&gap),
                std::mem::discriminant(&bounded)
            );
            let text = match &bounded {
                QueryReadIncomplete::SemanticEvidenceGap(x)
                | QueryReadIncomplete::ArtifactUnavailable(x)
                | QueryReadIncomplete::SemanticEvidenceUnavailable(x) => x,
                _ => panic!("text producer"),
            };
            assert!(text.len() <= brokk_bifrost_core::bounded_output::MAX_DIAGNOSTIC_MESSAGE_BYTES);
            assert!(text.contains("detail_kind=ProducerDiagnostic"));
            assert!(text.ends_with("omitted_items=1"));
        }
    }

    #[test]
    fn acquisition_and_runtime_budget_diagnostics_cannot_replay_as_artifacts() {
        for (code, cause) in [
            (JVM_DISCOVERY_SUPPRESSED, DerivationExecutionCause::Provider),
            (
                JVM_DEPENDENCY_UNAVAILABLE,
                DerivationExecutionCause::Provider,
            ),
            (JVM_INDEX_BUDGET, DerivationExecutionCause::Budget),
        ] {
            let diagnostic = ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Warning,
                code: code.code.into(),
                location: None,
                source_entry: None,
                declaration: None,
                message: "incomplete acquisition".into(),
            };
            let reason = classify(&diagnostic);
            assert_eq!(reason.execution_cause(), Some(cause));
            assert!(reason.stable_replay_reason().is_none());
        }
        let fixed = QueryReadIncomplete::ProofStopped {
            reason: "fixed_limit",
            cause: None,
        };
        assert_eq!(fixed.execution_cause(), None);
        assert_eq!(
            fixed.stable_replay_reason().as_deref(),
            Some("proof\0fixed_limit")
        );
    }
}
