use super::{
    TypeLookupDiagnostic, TypeLookupOutcome, TypeLookupStatus, TypeLookupType, no_type, sort_units,
};
use crate::analyzer::usages::get_definition::{
    CSharpTypeLookupResolution, csharp_type_lookup_resolution,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile, resolve_analyzer};
use tree_sitter::Tree;

pub(super) fn resolve_csharp_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("csharp_parse_failed", "C# source could not be parsed");
    };
    let support = analyzer.definition_lookup_index();
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return no_type("csharp_analyzer_unavailable", "C# analyzer is unavailable");
    };
    let Some(resolution) =
        csharp_type_lookup_resolution(analyzer, support, file, source, tree.root_node(), site)
    else {
        return no_type(
            "no_explicit_type",
            format!("`{}` does not have a supported explicit C# type", site.text),
        );
    };
    match resolution {
        CSharpTypeLookupResolution::Type {
            fqn,
            candidates,
            target_kind,
        } => csharp_candidates_outcome(csharp, fqn, candidates, target_kind),
        CSharpTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}

fn csharp_candidates_outcome(
    csharp: &CSharpAnalyzer,
    fqn: String,
    mut candidates: Vec<CodeUnit>,
    target_kind: crate::analyzer::usages::target_kind::TypeLookupTargetKind,
) -> TypeLookupOutcome {
    candidates = csharp_expand_logical_type_parts(csharp, candidates);
    sort_units(&mut candidates);
    candidates.dedup();
    let logical_type_count = csharp.logical_type_count(&candidates);
    let status = if logical_type_count <= 1 {
        TypeLookupStatus::Resolved
    } else {
        TypeLookupStatus::Ambiguous
    };
    let fqn = if status == TypeLookupStatus::Resolved {
        csharp.first_logical_type_fqn(&candidates).unwrap_or(fqn)
    } else {
        fqn
    };
    TypeLookupOutcome {
        status,
        reference: None,
        types: vec![TypeLookupType {
            fqn,
            definitions: candidates,
        }],
        diagnostics: if status == TypeLookupStatus::Ambiguous {
            vec![TypeLookupDiagnostic {
                kind: "ambiguous_type".to_string(),
                message: "reference resolved to multiple possible types".to_string(),
            }]
        } else {
            Vec::new()
        },
        target_kind,
    }
}

fn csharp_expand_logical_type_parts(
    csharp: &CSharpAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let mut expanded = Vec::new();
    for candidate in candidates {
        let parts = csharp.partial_type_parts(&candidate);
        if parts.is_empty() {
            expanded.push(candidate);
        } else {
            expanded.extend(parts);
        }
    }
    expanded
}
