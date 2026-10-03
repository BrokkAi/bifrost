//! Query-local annotation type proof; external route spelling is not proof.
use super::JavaAnalyzer;
use crate::CancellationToken;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, IAnalyzer, ProjectFile, QueryScope, Range,
    RelationalFrontierOutcome, resolve_analyzer,
};
use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource;
use brokk_bifrost_jvm::java::graph::JavaGraphSource;
use brokk_bifrost_jvm::java::graph::return_type::{
    LexicalTypeResolution, java_lexical_type_from_node, java_type_name_components,
};
use brokk_bifrost_jvm::java::graph_support::{
    JavaSourceTypeCandidates, java_type_parameter_in_scope,
    resolve_java_usage_type_component_candidates_in,
};
use brokk_bifrost_jvm::java::imports::{non_static_import_path, static_import_path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JavaAnnotationTypeStatus {
    Resolved,
    Ambiguous,
    Blocked,
    Incomplete,
    Unsupported,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct JavaAnnotationTypeResolution {
    pub status: JavaAnnotationTypeStatus,
    pub reason: Option<String>,
    pub source_declaration: Option<CodeUnit>,
    pub declaration_range: Option<Range>,
}

impl JavaAnnotationTypeResolution {
    fn gap(status: JavaAnnotationTypeStatus, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: Some(reason.into()),
            source_declaration: None,
            declaration_range: None,
        }
    }
}

/// Resolve the type named by exactly one annotation AST range in this snapshot.
/// This source stage deliberately does not authenticate external artifacts.
pub fn resolve_java_annotation_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    annotation_range: &Range,
    cancellation: &CancellationToken,
) -> JavaAnnotationTypeResolution {
    use JavaAnnotationTypeStatus as Status;
    if cancellation.is_cancelled() {
        return JavaAnnotationTypeResolution::gap(
            Status::Cancelled,
            "annotation resolution cancelled",
        );
    }
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return JavaAnnotationTypeResolution::gap(Status::Unsupported, "Java analyzer unavailable");
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let Some(prepared) = java.inner().prepared_syntax(token, file) else {
        return JavaAnnotationTypeResolution::gap(
            Status::Incomplete,
            "annotation source snapshot unavailable",
        );
    };
    if prepared.source() != source {
        return JavaAnnotationTypeResolution::gap(
            Status::Incomplete,
            "annotation source snapshot is stale",
        );
    }
    let root = prepared.tree().root_node();
    let Some(annotation) = root
        .named_descendant_for_byte_range(annotation_range.start_byte, annotation_range.end_byte)
    else {
        return JavaAnnotationTypeResolution::gap(
            Status::Unsupported,
            "annotation AST unavailable",
        );
    };
    if !matches!(annotation.kind(), "annotation" | "marker_annotation")
        || annotation.byte_range() != (annotation_range.start_byte..annotation_range.end_byte)
        || annotation.has_error()
    {
        return JavaAnnotationTypeResolution::gap(
            Status::Unsupported,
            "range does not identify one supported annotation AST",
        );
    }
    let Some(name) = annotation.child_by_field_name("name") else {
        return JavaAnnotationTypeResolution::gap(
            Status::Unsupported,
            "annotation AST has no type name",
        );
    };
    let Some(components) = java_type_name_components(name, source) else {
        return JavaAnnotationTypeResolution::gap(
            Status::Unsupported,
            "annotation type name syntax is unsupported",
        );
    };
    if java_type_parameter_in_scope(name, source, &components[0]).is_some() {
        return JavaAnnotationTypeResolution::gap(
            Status::Blocked,
            "a type parameter shadows the annotation type name",
        );
    }
    // The lexical helper can skip a nearer inherited member type while
    // resolving a declaration in an outer scope. Until that tier has proof,
    // neither an outer declaration nor an import is an exact answer.
    let mut owner = name.parent();
    while let Some(node) = owner {
        if node.child_by_field_name("superclass").is_some()
            || node.child_by_field_name("interfaces").is_some()
            || node.kind() == "object_creation_expression"
        {
            return JavaAnnotationTypeResolution::gap(
                Status::Incomplete,
                "inherited annotation member-type proof unavailable",
            );
        }
        owner = node.parent();
    }
    let resolution = crate::analyzer::relational_frontier::resolve_relational_frontier(
        analyzer,
        cancellation,
        |frontier| {
            let graph = JavaGraphSource {
                token,
                index: analyzer,
                hierarchy: analyzer.type_hierarchy_provider(),
                relational_definitions: frontier,
            };
            let unit = match java_lexical_type_from_node(java, token, &graph, file, source, name) {
                LexicalTypeResolution::Resolved(unit) => unit,
                LexicalTypeResolution::Blocked => {
                    return JavaAnnotationTypeResolution::gap(
                        Status::Blocked,
                        "lexical annotation type resolution is blocked",
                    );
                }
                LexicalTypeResolution::NotFound => {
                    // A static type-import route needs member-type proof, not a
                    // value lookup or a same-spelled ordinary import.
                    let imports = java.import_info_of(token, file);
                    if imports.iter().any(|import| {
                        static_import_path(import).is_some()
                            && (import.is_wildcard
                                || import.identifier.as_deref()
                                    == components.first().map(String::as_str))
                    }) {
                        return JavaAnnotationTypeResolution::gap(
                            Status::Incomplete,
                            "static annotation type-import proof unavailable",
                        );
                    }
                    if components.len() > 1 {
                        // A dotted annotation can start with a type binding,
                        // not only a package. Source-only route lookup cannot
                        // close same-package/on-demand/external type heads.
                        return JavaAnnotationTypeResolution::gap(
                            Status::Incomplete,
                            "qualified annotation type-head proof unavailable",
                        );
                    }
                    let file_types = java
                        .top_level_declarations(file)
                        .into_iter()
                        .filter(|unit| unit.is_class() && unit.identifier() == components[0])
                        .collect::<Vec<_>>();
                    if file_types.len() > 1
                        || (!file_types.is_empty()
                            && imports.iter().any(|import| {
                                !import.is_wildcard
                                    && non_static_import_path(import).is_some()
                                    && import.identifier.as_deref() == Some(components[0].as_str())
                            }))
                    {
                        return JavaAnnotationTypeResolution::gap(
                            Status::Ambiguous,
                            format!(
                                "annotation file type/import binding conflict: {file_types:?}, imports: {imports:?}"
                            ),
                        );
                    }
                    let candidates = if let Some(unit) = file_types.into_iter().next() {
                        JavaSourceTypeCandidates::Resolved(unit)
                    } else {
                        resolve_java_usage_type_component_candidates_in(
                            java,
                            token,
                            frontier,
                            file,
                            &components,
                        )
                    };
                    match candidates {
                        JavaSourceTypeCandidates::Resolved(unit) => unit,
                        JavaSourceTypeCandidates::Ambiguous(candidates) => {
                            return JavaAnnotationTypeResolution::gap(
                                Status::Ambiguous,
                                format!("annotation type candidates are ambiguous: {candidates:?}"),
                            );
                        }
                        JavaSourceTypeCandidates::Incomplete(candidates) => {
                            return JavaAnnotationTypeResolution::gap(
                                Status::Incomplete,
                                format!(
                                    "annotation dependency route or candidate coverage is incomplete: {candidates:?}"
                                ),
                            );
                        }
                        JavaSourceTypeCandidates::Unresolved => {
                            return JavaAnnotationTypeResolution::gap(
                                Status::Incomplete,
                                "annotation type has no source declaration or authenticated external artifact",
                            );
                        }
                    }
                }
            };
            if !java.has_complete_symbol_lookup_index() {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "Java declaration coverage is incomplete",
                );
            }
            if unit.is_synthetic() {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "synthetic annotation declaration lacks exact artifact proof",
                );
            }
            let Some(declaring) = java.inner().prepared_syntax(token, unit.source()) else {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "annotation declaration snapshot unavailable",
                );
            };
            let Some(declaration) = declaring.declaration_node(&unit) else {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "annotation declaration AST identity unavailable",
                );
            };
            if declaration.kind() != "annotation_type_declaration" || declaration.has_error() {
                return JavaAnnotationTypeResolution::gap(
                    Status::Unsupported,
                    "resolved declaration is not an annotation type",
                );
            }
            let PreparedSyntaxSource::Indexed(index) = declaring.backing() else {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "annotation declaration is not source indexed",
                );
            };
            let Some(ranges) = index.declaration_ranges(&unit) else {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "annotation declaration range unavailable",
                );
            };
            let Some(range) = ranges.iter().find(|range| {
                range.start_byte == declaration.start_byte()
                    && range.end_byte == declaration.end_byte()
            }) else {
                return JavaAnnotationTypeResolution::gap(
                    Status::Incomplete,
                    "annotation declaration range does not match its AST",
                );
            };
            JavaAnnotationTypeResolution {
                status: Status::Resolved,
                reason: None,
                source_declaration: Some(unit),
                declaration_range: Some(*range),
            }
        },
    );
    if cancellation.is_cancelled() {
        return JavaAnnotationTypeResolution::gap(
            Status::Cancelled,
            "annotation resolution cancelled",
        );
    }
    match resolution {
        RelationalFrontierOutcome::Complete(value) => value,
        RelationalFrontierOutcome::Cancelled => {
            JavaAnnotationTypeResolution::gap(Status::Cancelled, "annotation resolution cancelled")
        }
        RelationalFrontierOutcome::Failed(error) => JavaAnnotationTypeResolution::gap(
            Status::Incomplete,
            format!("annotation resolution frontier failed: {error:?}"),
        ),
    }
}
