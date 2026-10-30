//! Kotlin's usage-graph scans: the per-symbol forward scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both typing receivers through [`resolver`] -- the shared
//! Kotlin resolution library both usage paths read.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`KotlinGraphSource`].

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;

use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::{
    CodeUnit, CodeUnitIndex, DefinitionLanguageScope, RelationalDefinitionFrontier,
    RelationalDefinitionQuery, RelationalDefinitionQuestion, RelationalDefinitionValue,
    RelationalName,
};
use std::ops::ControlFlow;
use tree_sitter::Node;

/// The *dispatching* analyzer's side of a Kotlin usage-graph scan.
///
/// Deliberately not the Kotlin analyzer, for the reason recorded on
/// `JavaGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose relational frontier spans every language delegate and
/// whose hierarchy answers cross language boundaries. Kotlin depends on that
/// reach as much as Java does -- the JVM realm is one candidate space (#1237),
/// so a Kotlin file naming a Java or Scala class next door resolves only
/// through the workspace frontier.
#[derive(Clone)]
pub struct KotlinGraphSource<'a> {
    pub reads: brokk_bifrost_core::analyzer::project_reads::ReadCapability,
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub imports: Option<&'a dyn ImportAnalysisProvider>,
    /// Request-local answers for questions whose owner is already structured.
    pub relational_definitions: &'a dyn RelationalDefinitionFrontier,
}

impl KotlinGraphSource<'_> {
    pub fn definitions_by_components(&self, components: &[String]) -> Vec<CodeUnit> {
        let Some(identifier) = components.last() else {
            return Vec::new();
        };
        let mut identifier_name = FqName::new();
        identifier_name.push(segment_interner().intern(identifier, SegmentKind::Unknown));
        let question = RelationalDefinitionQuestion {
            language_scope: DefinitionLanguageScope::Workspace,
            name: RelationalName::stable(identifier_name),
            query: RelationalDefinitionQuery::Identifier { file: None },
        };
        let RelationalDefinitionValue::Definitions(candidates) =
            self.relational_definitions.ask(&question)
        else {
            panic!("a Kotlin identifier question returned the wrong shape")
        };
        let mut expected = FqName::new();
        for component in components {
            expected.push(segment_interner().intern(component, SegmentKind::Unknown));
        }
        candidates
            .into_iter()
            .filter(|unit| unit.fq().same_segment_texts(&expected))
            .collect()
    }

    pub fn structural_members(&self, owner: &FqName, identifier: &str) -> Vec<CodeUnit> {
        self.relational_definitions
            .structural_members(owner, identifier)
    }

    pub fn structural_children(&self, owner: &FqName) -> Vec<CodeUnit> {
        let question = RelationalDefinitionQuestion {
            language_scope: DefinitionLanguageScope::Workspace,
            name: RelationalName::stable(owner.clone()),
            query: RelationalDefinitionQuery::StructuralChildren,
        };
        match self.relational_definitions.ask(&question) {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => panic!("a structural-children question returned the wrong shape"),
        }
    }
}

pub(super) fn kotlin_constructed_type_components(
    callee_kind: &str,
    segments: &[Node<'_>],
    source: &str,
) -> Option<Vec<String>> {
    let names = segments.iter().map(|segment| node_text(*segment, source));
    let components: Vec<String> = if crate::kotlin::syntax::kotlin_is_navigation_kind(callee_kind) {
        let names = names.collect::<Vec<_>>();
        if names.iter().any(|name| name.is_empty()) {
            return None;
        }
        names.into_iter().map(str::to_string).collect()
    } else {
        names
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect()
    };
    (!components.is_empty()).then_some(components)
}

pub(super) fn kotlin_outer_user_type_segments(user_type: Node<'_>) -> Option<Vec<Node<'_>>> {
    if user_type
        .parent()
        .is_some_and(|parent| parent.kind() == "user_type")
    {
        return None;
    }
    Some(crate::kotlin::syntax::kotlin_user_type_segments(user_type))
}

pub(super) fn kotlin_navigation_receiver_identifier<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> Option<(Node<'tree>, &'source str)> {
    if crate::kotlin::syntax::kotlin_is_declaration_name(node) {
        return None;
    }
    let name = node_text(node, source);
    if name.is_empty() {
        return None;
    }
    let navigation = node
        .parent()
        .filter(|parent| crate::kotlin::syntax::kotlin_is_navigation_kind(parent.kind()))?;
    if crate::kotlin::syntax::kotlin_navigation_receiver(navigation)
        .is_none_or(|receiver| receiver.id() != node.id())
    {
        return None;
    }
    Some((navigation, name))
}

pub(super) fn visit_resolved_type_name_prefixes<'tree>(
    segments: &[Node<'tree>],
    source: &str,
    names: &resolver::KotlinNameResolver<'_>,
    mut visit: impl FnMut(Node<'tree>, String) -> ControlFlow<()>,
) {
    let mut components = Vec::new();
    for segment in segments {
        let name = node_text(*segment, source);
        if name.is_empty() {
            return;
        }
        components.push(name.to_string());
        if let Some(resolved) = names.resolve_type_components(&components, segment.start_byte())
            && let ControlFlow::Break(()) = visit(*segment, resolved)
        {
            return;
        }
    }
}
