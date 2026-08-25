//! Java's usage-graph scans: the per-symbol forward scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`] and
//! [`return_type`] -- the shared Java resolution library the definition route
//! also reads.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`JavaGraphSource`] plus the
//! [`JavaSource`](crate::java::graph_support::JavaSource) the memoized Java
//! products come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;
pub mod return_type;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{
    CodeUnit, CodeUnitIndex, DefinitionLanguageScope, ProjectFile, RelationalDefinitionFrontier,
    RelationalDefinitionQuery, RelationalDefinitionQuestion, RelationalDefinitionValue,
    RelationalName,
};

/// The *dispatching* analyzer's side of a Java usage-graph scan.
///
/// Deliberately not the Java analyzer, for the reason recorded on
/// `PythonGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose relational frontier spans every language delegate and
/// whose `get_ancestors` crosses language boundaries. Java depends on that
/// reach twice over -- the JVM realm is one candidate space (#1237), so a Java
/// file naming a Kotlin or Scala class next door resolves only through the
/// workspace frontier -- so this stays separate from the
/// [`JavaSource`](crate::java::graph_support::JavaSource) that answers the
/// Java-only questions.
#[derive(Clone, Copy)]
pub struct JavaGraphSource<'a> {
    /// Proof that a request scope is open: the import accessors reached from
    /// this source cross the import tier's storage (issue #2423).
    pub token: QueryToken<'a>,
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    /// Request-local store answers for structured graph questions.
    pub relational_definitions: &'a dyn RelationalDefinitionFrontier,
    pub import_statements: &'a ImportStatementAccess<'a>,
}

/// See [`JavaGraphSource::import_statements`]: the raw `import` statement text
/// of a file, which `IAnalyzer` answers from persisted per-file state rather
/// than from the structured import facts.
pub type ImportStatementAccess<'a> = dyn Fn(&ProjectFile) -> Vec<String> + Sync + 'a;

impl JavaGraphSource<'_> {
    /// Every direct child of `owner` named `identifier`, read from the
    /// request-local relational frontier. The owner is already a structured
    /// declaration identity, so no rendered Java name is reconstructed here.
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
}
