//! The analysis-side entry point for C#'s semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_csharp::diagnostics`]. What
//! stays here is what that crate cannot name: the downcast that produces the
//! C# analysis source, and the retained external surface -- the assembly
//! declaration index plus the dependency-discovery evidence -- that answers
//! what the workspace's compiled references prove about a name.
//!
//! Every read below is a *peek*. [`CSharpAnalyzer::retained_external_index`]
//! is `OnceLock::get`, never `get_or_init`, because
//! `CSharpExternalDeclarationIndex::build_for_project` walks the project for
//! `project.assets.json` files and decodes assembly metadata, and #1615 forbids
//! that work inside a diagnostic request. An index no earlier resolution or
//! [`IAnalyzer::warm_query_indexes`] pass has built is an unknown boundary, not
//! a reason to go and build one.
//!
//! Both call sites pass the *dispatching* analyzer, because the retained
//! discovery evidence is published on the analyzer a host ran discovery
//! against, which in a workspace is the composite one and not the C# delegate.

use std::sync::Arc;

use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, ProducerDiagnosticSeverity,
    dependency_discovery_incomplete_reasons,
};
use crate::analyzer::structural::BoundaryStatus;
use crate::analyzer::{
    CSharpAnalyzer, IAnalyzer, Language, ProjectFile, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport, resolve_analyzer,
};
use crate::hash::HashSet;
use brokk_bifrost_csharp::diagnostics::{
    CSharpExternalEvidence, CSharpExternalTypes, CSharpMemberSurface,
};

use super::external::CSharpExternalDeclarationIndex;

pub(crate) fn collect_csharp_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        let mut report = SemanticDiagnosticReport::new();
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "no C# analyzer serves this file".to_string(),
            }],
        );
        return report;
    };
    let external = RetainedCSharpExternal {
        csharp,
        index: csharp.retained_external_index(),
        evidence: analyzer.dependency_discovery_evidence(Language::CSharp),
    };
    brokk_bifrost_csharp::diagnostics::collect_csharp_semantic_diagnostics(
        csharp, &external, file, source,
    )
}

/// The external C# facts a diagnostic request may read: the assembly index an
/// earlier pass built, and what a discovery run retained. Both are analyzer
/// state a host produced earlier. Nothing here reads an assembly, opens
/// `project.assets.json`, or starts discovery.
struct RetainedCSharpExternal<'a> {
    csharp: &'a CSharpAnalyzer,
    index: Option<&'a CSharpExternalDeclarationIndex>,
    evidence: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl RetainedCSharpExternal<'_> {
    /// Why an index that was never built cannot answer.
    ///
    /// Discovery evidence refines the boundary: no discovery at all is
    /// `ExternalUnknown`, a discovery that could not read everything is
    /// `Truncated`, and a complete discovery whose artifacts nothing has
    /// indexed yet is `ExternalDeclaredUnindexed`.
    fn unbuilt_reason(&self) -> SemanticDiagnosticIncompleteReason {
        dependency_discovery_incomplete_reasons(self.evidence.as_deref())
            .pop()
            .unwrap_or(
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                },
            )
    }
}

impl CSharpExternalEvidence for RetainedCSharpExternal<'_> {
    fn unreadable(&self) -> Option<SemanticDiagnosticIncompleteReason> {
        let Some(index) = self.index else {
            return Some(self.unbuilt_reason());
        };
        if index.is_complete() {
            return None;
        }
        // Truncated or malformed metadata holds an unknown remainder, so no
        // miss against this index proves anything. An error names a pack that
        // could not be decoded; a warning means the decode gave up part way.
        let worst = index
            .production_diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.severity == ProducerDiagnosticSeverity::Error);
        Some(match worst {
            Some(diagnostic) => SemanticDiagnosticIncompleteReason::CorruptSemanticPack {
                detail: format!("{}: {}", diagnostic.code, diagnostic.message),
            },
            None => SemanticDiagnosticIncompleteReason::Truncated,
        })
    }

    fn surface_is_known(&self) -> bool {
        self.index
            .is_some_and(|index| index.is_complete() && index.has_dependency_inputs())
    }

    fn declares_namespace(&self, namespace: &str) -> bool {
        self.index
            .is_some_and(|index| index.declares_namespace(namespace))
    }

    fn resolve_type(&self, file: &ProjectFile, identity: &str) -> CSharpExternalTypes {
        let Some(index) = self.index else {
            return CSharpExternalTypes::None;
        };
        // The same four inputs `CSharpAnalyzer::external_type_candidates`
        // resolves with, read from the analyzer's memo cells rather than
        // recomputed.
        let matched = index.resolve_in_file(
            identity,
            &self.csharp.namespace_of_file(file),
            &self.csharp.using_namespaces_of(file),
            &self.csharp.using_aliases_of(file),
        );
        // Two assemblies publishing the same identity are one type as far as a
        // name lookup is concerned; only distinct identities are an ambiguity.
        let distinct: HashSet<&str> = matched.iter().map(|ty| ty.fqn()).collect();
        let mut identities = distinct.into_iter();
        match (identities.next(), identities.len()) {
            (None, _) => CSharpExternalTypes::None,
            (Some(fqn), 0) => CSharpExternalTypes::One {
                fqn: fqn.to_string(),
            },
            (Some(_), rest) => CSharpExternalTypes::Many { count: rest + 1 },
        }
    }

    fn resolve_member(&self, owner_fqn: &str, member: &str) -> CSharpMemberSurface {
        let Some(index) = self.index else {
            return CSharpMemberSurface::IncompleteOwner {
                detail: "the C# assembly index is not built".to_string(),
            };
        };
        // The owner's whole surface is its own members plus every ancestor's,
        // so the walk only reports absence once it has reached the root of the
        // chain. A link this index does not hold ends it as incomplete: the
        // members that link would have contributed are exactly the unknown
        // part (#1789).
        let mut seen: HashSet<String> = HashSet::default();
        seen.insert(owner_fqn.to_string());
        let mut pending = vec![owner_fqn.to_string()];
        while let Some(current) = pending.pop() {
            let declarations = index.types_named(&current);
            if declarations.is_empty() {
                return CSharpMemberSurface::IncompleteOwner {
                    detail: format!(
                        "`{current}` in the supertype chain of `{owner_fqn}` is not in the retained assembly index"
                    ),
                };
            }
            if !index.members_named(&current, member).is_empty() {
                return CSharpMemberSurface::Published;
            }
            for declaration in declarations {
                for supertype in declaration.supertype_names() {
                    if seen.insert(supertype.to_string()) {
                        pending.push(supertype.to_string());
                    }
                }
            }
        }
        CSharpMemberSurface::Absent
    }

    fn could_supply_extension_method(&self, namespaces: &[String], name: &str) -> bool {
        self.index
            .is_some_and(|index| index.declares_static_method_in(namespaces, name))
    }
}
