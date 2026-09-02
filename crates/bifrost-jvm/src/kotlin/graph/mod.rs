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
use brokk_bifrost_core::analyzer::{
    CodeUnit, CodeUnitIndex, DefinitionLanguageScope, RelationalDefinitionFrontier,
    RelationalDefinitionQuery, RelationalDefinitionQuestion, RelationalDefinitionValue,
    RelationalName,
};

/// The *dispatching* analyzer's side of a Kotlin usage-graph scan.
///
/// Deliberately not the Kotlin analyzer, for the reason recorded on
/// `JavaGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose relational frontier spans every language delegate and
/// whose hierarchy answers cross language boundaries. Kotlin depends on that
/// reach as much as Java does -- the JVM realm is one candidate space (#1237),
/// so a Kotlin file naming a Java or Scala class next door resolves only
/// through the workspace frontier.
#[derive(Clone, Copy)]
pub struct KotlinGraphSource<'a> {
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
        let question = RelationalDefinitionQuestion {
            language_scope: DefinitionLanguageScope::Workspace,
            name: RelationalName::stable(owner.clone()),
            query: RelationalDefinitionQuery::StructuralMembers {
                identifier: identifier.to_string(),
            },
        };
        match self.relational_definitions.ask(&question) {
            RelationalDefinitionValue::Definitions(units) => units,
            _ => panic!("a structural-member question returned the wrong shape"),
        }
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
