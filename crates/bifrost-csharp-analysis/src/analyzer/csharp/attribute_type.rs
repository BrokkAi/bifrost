//! The type one C# attribute application names.
//!
//! C# looks an attribute name up as a type, trying the written spelling and
//! the same spelling with `Attribute` appended. A workspace declaration proves
//! itself. Otherwise the external declaration surface (referenced assemblies
//! and active semantic packs) must declare exactly one identity for the
//! spellings the C# name ladder produces. A namespace `using` does not fix a
//! qualified name by itself, so an attribute neither surface declares stays
//! incomplete rather than guessed from the spelling.

use crate::analyzer::csharp::CSharpAnalyzer;
use crate::analyzer::csharp::external::CSharpExternalTypeLookup;
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_csharp::graph::resolver::attribute_type_candidates_of_name;
use brokk_bifrost_csharp::graph_support::CSharpLookupContext;
use brokk_bifrost_csharp::syntax::csharp_attribute_type_names;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpAttributeTypeStatus {
    Resolved,
    Ambiguous,
    Incomplete,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct CSharpAttributeTypeResolution {
    pub status: CSharpAttributeTypeStatus,
    pub fq_name: Option<String>,
    /// The workspace declaration, when the attribute class is in source.
    pub source_declaration: Option<CodeUnit>,
    pub reason: Option<String>,
}

impl CSharpAttributeTypeResolution {
    fn gap(status: CSharpAttributeTypeStatus, reason: impl Into<String>) -> Self {
        Self {
            status,
            fq_name: None,
            source_declaration: None,
            reason: Some(reason.into()),
        }
    }
}

/// Resolve the attribute class an `attribute` node applies.
pub fn resolve_csharp_attribute_type(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    attribute: Node<'_>,
) -> CSharpAttributeTypeResolution {
    use CSharpAttributeTypeStatus as Status;
    assert_eq!(attribute.kind(), "attribute");
    if attribute.has_error() {
        return CSharpAttributeTypeResolution::gap(
            Status::Unsupported,
            "attribute syntax was recovered",
        );
    }
    let Some(name) = attribute.child_by_field_name("name") else {
        return CSharpAttributeTypeResolution::gap(Status::Unsupported, "attribute has no name");
    };
    let (workspace, ambiguous) =
        attribute_type_candidates_of_name(csharp, token, file, name, source);
    if ambiguous {
        return CSharpAttributeTypeResolution::gap(
            Status::Ambiguous,
            format!("attribute names more than one workspace class: {workspace:?}"),
        );
    }
    if let Some(unit) = workspace.first() {
        return CSharpAttributeTypeResolution {
            status: Status::Resolved,
            fq_name: Some(unit.fq_name()),
            source_declaration: Some(unit.clone()),
            reason: None,
        };
    }
    let Some(context) = CSharpLookupContext::at(source, name, || true) else {
        return CSharpAttributeTypeResolution::gap(
            Status::Unsupported,
            "attribute has no lookup context",
        );
    };
    let external = csharp.external_declarations(analyzer.semantic_model_overlay());
    let usings = csharp.using_namespaces_of(token, file);
    let aliases = csharp.using_aliases_of(token, file);
    let mut identities = Vec::new();
    for spelling in csharp_attribute_type_names(name, source) {
        match external.resolve_type_in_file(&spelling, context.namespace(), &usings, &aliases) {
            CSharpExternalTypeLookup::Unique(candidate) => identities.push(candidate.fqn),
            CSharpExternalTypeLookup::Absent => {}
            CSharpExternalTypeLookup::Ambiguous => {
                return CSharpAttributeTypeResolution::gap(
                    Status::Ambiguous,
                    format!("external declarations of `{spelling}` are ambiguous"),
                );
            }
        }
    }
    identities.sort();
    identities.dedup();
    match identities.as_slice() {
        [fq_name] => CSharpAttributeTypeResolution {
            status: Status::Resolved,
            fq_name: Some(fq_name.clone()),
            source_declaration: None,
            reason: None,
        },
        [] => CSharpAttributeTypeResolution::gap(
            Status::Incomplete,
            "attribute type has no workspace declaration or external declaration",
        ),
        _ => CSharpAttributeTypeResolution::gap(
            Status::Ambiguous,
            format!("attribute spellings name more than one external type: {identities:?}"),
        ),
    }
}
