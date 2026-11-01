//! Anonymous JVM type owners share ordinary member scopes and hierarchy facts.
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionIdentifierRole, ResolutionNameId,
    ResolutionNamespace, ResolutionScopeId, ResolutionScopeKind, ResolutionSiteId,
    ResolutionSiteKind,
};

/// Grammar hooks supply a body site and intern its private identity. The body
/// has no source declaration bridge, source binder or user-visible label.
#[derive(Clone, Copy)]
pub(crate) struct AnonymousTypeBody {
    pub(crate) site: ResolutionSiteId,
    pub(crate) name: ResolutionNameId,
}

impl AnonymousTypeBody {
    pub(crate) fn name(body: tree_sitter::Node<'_>) -> String {
        let node = body
            .parent()
            .expect("anonymous body has an expression owner");
        if matches!(node.kind(), "object_creation_expression" | "enum_constant") {
            return crate::java::declarations::java_synthetic_name(node);
        }
        brokk_bifrost_core::analyzer::tree_walk::synthetic_name(
            node,
            |candidate| (candidate.kind() == "object_literal").then_some("anon"),
            |candidate| {
                matches!(
                    candidate.kind(),
                    "function_declaration"
                        | "secondary_constructor"
                        | "class_declaration"
                        | "object_declaration"
                )
            },
        )
        .to_string()
    }

    pub(crate) fn declare(self, facts: &mut FileResolutionFacts) {
        let site = facts.sites[self.site.index()];
        assert_eq!(site.kind, ResolutionSiteKind::TypeDeclaration);
        assert!(
            facts
                .identifiers
                .iter()
                .all(|identifier| identifier.site != self.site)
        );
        facts.identifiers.push(PositionedIdentifierFact {
            site: self.site,
            name: self.name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Type,
            qualifier: None,
        });
    }

    pub(crate) fn open_scope(self, facts: &mut FileResolutionFacts) -> ResolutionScopeId {
        let site = facts.sites[self.site.index()];
        assert!(
            facts
                .identifiers
                .iter()
                .any(|identifier| identifier.site == self.site
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type)
        );
        facts.allocate_lexical_scope(
            site.scope,
            Some(self.site),
            ResolutionScopeKind::TypeBody,
            site.start_byte,
            site.end_byte,
        )
    }
}
