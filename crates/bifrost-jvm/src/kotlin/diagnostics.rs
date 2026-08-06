//! Kotlin semantic diagnostics (#1243).
//!
//! Collects high-confidence unresolved-type diagnostics only: an unqualified
//! type reference is reported iff it resolves through NEITHER the file's
//! imports, its own package, star imports, Kotlin's default imports, the
//! wider JVM source realm (when a realm view is supplied — see
//! [`collect_kotlin_semantic_diagnostics`]'s `realm` parameter), NOR the
//! external dependency index. Anything reachable only through an
//! unconfigured classpath stays silent — that is the suppression contract
//! documented in `kotlin/mod.rs`'s module header — and a name that Kotlin
//! itself would reject as *ambiguous* (two star imports binding the same
//! spelling to different owners) is likewise never reported as unrecognized:
//! ambiguity is a real, structurally-known answer, not evidence that nothing
//! was found.
//!
//! Members, functions, and properties are deliberately not diagnosed here:
//! Kotlin resolves those through overload sets, extension-function scope, and
//! operator conventions this module does not model, so a wrong answer there
//! is far likelier than for a bare type name.
//!
//! The `SemanticDiagnostic` this lowers into and the analyzer that supplies the
//! enclosing-declaration lookup both stay in `brokk-bifrost-analysis`, so the
//! collector below hands back its own record and takes the enclosing owner's
//! scope as a `&dyn CodeUnitIndex` query.

use brokk_bifrost_core::analyzer::model::{ImportInfo, Range, SemanticDiagnostic};
use brokk_bifrost_core::analyzer::semantic_diagnostics::node_range;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::{Node, Parser, Tree};

use crate::kotlin::graph_support::KotlinSource;
use crate::kotlin::syntax::{kotlin_enclosing_import_header, kotlin_type_spelling};
use crate::kotlin::types::{
    KotlinNameScope, kotlin_scope_owners_for, kotlin_type_name_definitely_unresolved_in_realm,
};
use crate::realm::JvmSourceRealm;

pub const KOTLIN_UNRECOGNIZED_SYMBOL: &str = "kotlin_unrecognized_symbol";
pub const KOTLIN_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-kotlin";
const MAX_KOTLIN_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_KOTLIN_SEMANTIC_DIAGNOSTICS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KotlinSemanticDiagnostic {
    pub range: Range,
    pub kind: &'static str,
    pub message: String,
}

impl From<KotlinSemanticDiagnostic> for SemanticDiagnostic {
    fn from(diagnostic: KotlinSemanticDiagnostic) -> Self {
        Self {
            range: diagnostic.range,
            source: KOTLIN_SEMANTIC_DIAGNOSTIC_SOURCE,
            kind: diagnostic.kind,
            message: diagnostic.message,
        }
    }
}

/// Collect high-confidence Kotlin unresolved-type diagnostics for `file`.
///
/// `realm` widens resolution across the whole JVM source realm (Java/Scala
/// siblings in the same workspace) when supplied by `MultiAnalyzer`; a bare
/// `KotlinAnalyzer` passes `None` and resolves against its own declarations
/// and the external dependency index only.
///
/// `owners` is the dispatching analyzer's enclosing-declaration lookup, which
/// in a mixed workspace crosses language boundaries; `kotlin` is the Kotlin
/// analyzer's own resolution surface.
pub fn collect_kotlin_semantic_diagnostics(
    owners: &dyn CodeUnitIndex,
    kotlin: &dyn KotlinSource,
    file: &ProjectFile,
    source: &str,
    realm: Option<&JvmSourceRealm<'_>>,
) -> Vec<KotlinSemanticDiagnostic> {
    if source.len() > MAX_KOTLIN_SEMANTIC_DIAGNOSTIC_BYTES {
        return Vec::new();
    }
    let Some(tree) = parse_kotlin_tree(source) else {
        return Vec::new();
    };
    let mut parse_errors = Vec::new();
    collect_parse_errors(tree.root_node(), &mut parse_errors);
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let line_starts = compute_line_starts(source);
    let package_name = kotlin.package_name_of(file).unwrap_or_default();
    let imports = kotlin.import_info_of(file);
    let mut collector = KotlinDiagnosticCollector {
        owners,
        kotlin,
        file,
        source,
        line_starts: &line_starts,
        package_name,
        imports,
        realm,
        diagnostics: Vec::new(),
    };
    collector.scan_tree(tree.root_node());
    collector.diagnostics
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
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    package_name: String,
    imports: Vec<ImportInfo>,
    realm: Option<&'a JvmSourceRealm<'a>>,
    diagnostics: Vec<KotlinSemanticDiagnostic>,
}

impl KotlinDiagnosticCollector<'_> {
    fn scan_tree(&mut self, root: Node<'_>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.diagnostics.len() >= MAX_KOTLIN_SEMANTIC_DIAGNOSTICS {
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
        if !kotlin_type_name_definitely_unresolved_in_realm(self.kotlin, &scope, &name, self.realm)
        {
            return;
        }
        self.diagnostics.push(KotlinSemanticDiagnostic {
            range: node_range(node, self.line_starts),
            kind: KOTLIN_UNRECOGNIZED_SYMBOL,
            message: format!("Unrecognized Kotlin type `{name}`"),
        });
    }
}
