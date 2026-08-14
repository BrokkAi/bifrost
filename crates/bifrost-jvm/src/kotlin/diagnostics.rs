//! Kotlin semantic diagnostics (#1243, proof-gated by #1619).
//!
//! Every unqualified type reference a Kotlin file spells is classified through
//! [`kotlin_type_name_proof`]: the file's imports, its own package, star
//! imports, Kotlin's default imports, the wider JVM source realm (when a realm
//! view is supplied -- see [`collect_kotlin_semantic_diagnostics`]'s `realm`
//! parameter), the retained external dependency index, and the active
//! dependency model, in that order.
//!
//! What used to be silence is now a typed outcome. A name reachable only
//! through an unconfigured or unread classpath was suppressed before and is
//! suppressed still, but the report now says why:
//! `MissingDependencyDiscovery` naming the exact boundary. A name Kotlin itself
//! would reject as *ambiguous* -- two star imports binding one spelling to
//! different owners -- records `Ambiguous`, because ambiguity is a real,
//! structurally-known answer, not evidence that nothing was found. Only a name
//! that every retained surface was able to miss becomes an error.
//!
//! Members, functions, and properties are deliberately not diagnosed here:
//! Kotlin resolves those through overload sets, extension-function scope, and
//! operator conventions this module does not model, so a wrong answer there
//! is far likelier than for a bare type name. See [`crate::proof`] on why no
//! JVM language can claim a `MemberSurface` domain today.

use brokk_bifrost_core::analyzer::model::{
    ImportInfo, SemanticDiagnostic, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::node_range;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

use crate::kotlin::graph_support::KotlinSource;
use crate::kotlin::syntax::{kotlin_enclosing_import_header, kotlin_type_spelling};
use crate::kotlin::types::{KotlinNameScope, kotlin_scope_owners_for, kotlin_type_name_proof};
use crate::proof::{JvmActiveSemanticModel, record_jvm_name_proof};
use crate::realm::JvmSourceRealm;

pub const KOTLIN_UNRECOGNIZED_SYMBOL: &str = "kotlin_unrecognized_symbol";
pub const KOTLIN_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-kotlin";
const MAX_KOTLIN_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_KOTLIN_SEMANTIC_DIAGNOSTICS: usize = 200;

/// Collect proof-gated Kotlin unresolved-type diagnostics for `file`.
///
/// `realm` widens resolution across the whole JVM source realm (Java/Scala
/// siblings in the same workspace) when supplied by `MultiAnalyzer`; a bare
/// `KotlinAnalyzer` passes `None` and resolves against its own declarations
/// and the retained dependency surfaces only.
///
/// `owners` is the dispatching analyzer's enclosing-declaration lookup, which
/// in a mixed workspace crosses language boundaries; `kotlin` is the Kotlin
/// analyzer's own resolution surface; `model` is the dispatching analyzer's
/// active dependency model.
pub fn collect_kotlin_semantic_diagnostics(
    owners: &dyn CodeUnitIndex,
    kotlin: &dyn KotlinSource,
    file: &ProjectFile,
    source: &str,
    realm: Option<&JvmSourceRealm<'_>>,
    model: &dyn JvmActiveSemanticModel,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_KOTLIN_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }
    let Some(tree) = parse_kotlin_tree(source) else {
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "Kotlin source did not parse".to_string(),
            }],
        );
        return report;
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        // A file the parser could not read has no reliable reference sites, so
        // no name in it can be proved absent. The LSP still publishes the parse
        // errors themselves through its own path.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("Kotlin source has {} parse errors", parse_errors.len()),
            }],
        );
        return report;
    }

    let line_starts = compute_line_starts(source);
    let package_name = kotlin.package_name_of(file).unwrap_or_default();
    let imports = kotlin.import_info_of(file);
    let mut collector = KotlinDiagnosticCollector {
        owners,
        kotlin,
        model,
        file,
        source,
        line_starts: &line_starts,
        package_name,
        imports,
        realm,
        report,
        errors: 0,
    };
    collector.scan_tree(tree.root_node());
    collector.report
}

fn parse_kotlin_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::kotlin::language::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

struct KotlinDiagnosticCollector<'a> {
    owners: &'a dyn CodeUnitIndex,
    kotlin: &'a dyn KotlinSource,
    model: &'a dyn JvmActiveSemanticModel,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    package_name: String,
    imports: Vec<ImportInfo>,
    realm: Option<&'a JvmSourceRealm<'a>>,
    report: SemanticDiagnosticReport,
    errors: usize,
}

impl KotlinDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.errors >= MAX_KOTLIN_SEMANTIC_DIAGNOSTICS {
                self.report
                    .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                break;
            }
            if node.kind() == "user_type" && kotlin_enclosing_import_header(node).is_none() {
                self.check_user_type(node);
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.into_iter().rev());
        }
    }

    fn check_user_type(&mut self, node: Node<'_>) {
        let Some(name) = kotlin_type_spelling(node, self.source) else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let scope_owners = self
            .owners
            .enclosing_code_unit_for_lines(
                self.file,
                node.start_position().row,
                node.end_position().row,
            )
            .map(|owner| kotlin_scope_owners_for(self.kotlin, &owner))
            .unwrap_or_default();
        let scope = KotlinNameScope {
            package_name: &self.package_name,
            imports: &self.imports,
            scope_owners,
        };
        let proof = kotlin_type_name_proof(self.kotlin, &scope, &name, self.realm, self.model);
        let range = node_range(node, self.line_starts);
        if record_jvm_name_proof(&mut self.report, range, proof, || {
            (
                SemanticDiagnosticDomain::Type { name: name.clone() },
                SemanticDiagnostic {
                    range,
                    source: KOTLIN_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind: KOTLIN_UNRECOGNIZED_SYMBOL,
                    message: format!("Unrecognized Kotlin type `{name}`"),
                },
            )
        }) {
            self.errors += 1;
        }
    }
}
