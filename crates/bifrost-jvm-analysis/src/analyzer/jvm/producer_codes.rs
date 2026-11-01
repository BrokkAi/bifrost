//! Diagnostic stability for JVM external-index producers.

use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
use brokk_bifrost_analysis::analyzer::semantic_model::ProducerDiagnostic;

#[derive(Clone, Copy)]
pub(crate) enum CodeClass {
    Gap,
    Artifact,
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
    let detail = || format!("{}: {}", diagnostic.code, diagnostic.message).into_boxed_str();
    match class_of(&diagnostic.code) {
        Some(CodeClass::Gap) => QueryReadIncomplete::SemanticEvidenceGap(detail()),
        Some(CodeClass::Artifact) => QueryReadIncomplete::ArtifactUnavailable(detail()),
        Some(CodeClass::Fallback) | None => {
            brokk_bifrost_analysis::analyzer::common::external_index_incompleteness(diagnostic)
        }
    }
}
