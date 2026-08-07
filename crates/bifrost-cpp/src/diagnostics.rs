//! C++'s semantic diagnostics: unrecognized-type reporting with stated proof.
//!
//! The pass reports a missing type only where it can prove what a translation
//! unit sees: a `compile_commands.json` entry with no forced or system
//! includes, an `#include` closure of quoted project headers that all resolve
//! and parse cleanly, and no preprocessor conditionals or macro definitions
//! anywhere in that closure. That gate is unchanged. What changed in #1627 is
//! that every way of failing it now states a typed
//! [`SemanticDiagnosticIncompleteReason`] instead of returning silence: "this
//! file has no unknown types" and "this file was never checked" are different
//! answers, and only the first may be read as a clean bill of health.
//!
//! Nothing here runs a compiler, a build tool, or a system include scan. The
//! compile database is the whole of the external evidence, so a file the
//! database does not name is unjudgeable rather than clean.
//!
//! `analyzer/cpp/diagnostics.rs` in `brokk-bifrost-analysis` keeps only the
//! fixtures that build a real `CppAnalyzer`.

use crate::compile_context::CppCompileContext;
use crate::graph_support::CppSource;
use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::semantic_diagnostics::{node_range, node_text};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;
use brokk_bifrost_core::analyzer::{ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_core::text_utils::compute_line_starts;
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

pub const CPP_UNRECOGNIZED_SYMBOL: &str = "cpp_unrecognized_symbol";
pub const CPP_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-cpp";
const MAX_CPP_SEMANTIC_DIAGNOSTIC_BYTES: usize = 512 * 1024;
const MAX_CPP_SEMANTIC_DIAGNOSTICS: usize = 200;

pub fn collect_cpp_semantic_diagnostics(
    analyzer: &dyn CppSource,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let mut report = SemanticDiagnosticReport::new();
    if source.len() > MAX_CPP_SEMANTIC_DIAGNOSTIC_BYTES {
        report.push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
        return report;
    }

    let tree = parse_cpp_tree(source);
    if has_parse_errors(tree.root_node()) {
        // The parse errors themselves reach the host through the analyzer's
        // parse-diagnostic path. What this report records is that the tree this
        // pass would have judged is not trustworthy, so no name was checked.
        report.push_incomplete(
            None,
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: "C++ source has parse errors".to_string(),
            }],
        );
        return report;
    }

    // The compile database is the only external evidence C++ has. A file it
    // does not name may still be compiled, with flags and an include path this
    // pass cannot see, so its boundary is unknown rather than empty.
    let contexts = analyzer.compile_contexts_for(file);
    if contexts.is_empty() {
        report.push_incomplete(
            None,
            vec![
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                },
            ],
        );
        return report;
    }

    let mut closures = Vec::with_capacity(contexts.len());
    for context in contexts {
        match prove_include_closure(file, source, context) {
            Ok(closure) => closures.push((context, closure)),
            // One unprovable configuration sinks the file: a name absent from
            // the configurations that did prove out may well be present in the
            // one that did not.
            Err(reason) => {
                report.push_incomplete(None, vec![reason]);
                return report;
            }
        }
    }

    let line_starts = compute_line_starts(source);
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_identifier" && is_plain_type_reference(node) {
            let name = node_text(node, source);
            if !name.is_empty() {
                if report.diagnostics().len() >= MAX_CPP_SEMANTIC_DIAGNOSTICS {
                    report
                        .push_incomplete(None, vec![SemanticDiagnosticIncompleteReason::Truncated]);
                    break;
                }
                record_type_reference(&mut report, &closures, name, node_range(node, &line_starts));
            }
        }
        push_named_children(&mut stack, node);
    }
    report
}

/// Judge one type reference against every proven closure and record what the
/// closures could show.
fn record_type_reference(
    report: &mut SemanticDiagnosticReport,
    closures: &[(&CppCompileContext, ProvenClosure)],
    name: &str,
    range: Range,
) {
    let mut resolutions = closures
        .iter()
        .map(|(context, closure)| closure.resolve(context, name));
    let first = resolutions.next().expect("at least one proven closure");
    if resolutions.any(|resolution| resolution != first) {
        // The configurations disagree, so neither presence nor absence holds
        // for the file as a whole. Naming the type keeps the report actionable.
        report.push_incomplete(
            Some(range),
            vec![SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!("the compile commands for this file disagree about type `{name}`"),
            }],
        );
        return;
    }

    match first {
        NameResolution::CommandLineMacro => {
            // `-DFoo=...` makes the build, not the closure, decide what this
            // name spells. Expanding it would mean running the preprocessor.
            report.push_incomplete(
                Some(range),
                vec![
                    SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
                        detail: format!(
                            "type name `{name}` is defined as a compile-command macro (-D{name})"
                        ),
                    },
                ],
            );
        }
        NameResolution::Declared { definition_sites } if definition_sites > 1 => {
            // This pass matches on the bare name, so two definitions of it in
            // the closure (two namespaces, most often) leave it unable to say
            // which one the reference means. Both are workspace-local.
            report.push_ambiguous(
                range,
                vec![BoundaryStatus::WorkspaceLocal; definition_sites],
            );
        }
        NameResolution::Declared { .. } => {
            report.push_resolved(range, BoundaryStatus::WorkspaceLocal);
        }
        NameResolution::Absent => {
            // The proven closure is entirely project-local, so a name missing
            // from it is missing from everything the translation unit sees.
            report.push_absent(
                SemanticAbsenceProof {
                    range,
                    domain: SemanticDiagnosticDomain::Type {
                        name: name.to_string(),
                    },
                    boundary: BoundaryStatus::WorkspaceLocal,
                },
                SemanticDiagnostic {
                    range,
                    source: CPP_SEMANTIC_DIAGNOSTIC_SOURCE,
                    kind: CPP_UNRECOGNIZED_SYMBOL,
                    message: format!("Unrecognized C++ type `{name}`"),
                },
            );
        }
    }
}

/// What one compile configuration's include closure says about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameResolution {
    /// The compile command defines the name as a macro, so the closure is not
    /// the thing that decides what it means.
    CommandLineMacro,
    /// No specifier in the closure names it.
    Absent,
    /// The closure names it, at `definition_sites` places that give it a body.
    /// Zero sites means a forward declaration and nothing more, which still
    /// makes the name a type this translation unit knows.
    Declared { definition_sites: usize },
}

/// Every type name one compile configuration's `#include` closure introduces.
#[derive(Debug, Default)]
struct ProvenClosure {
    /// Names introduced by any class, struct, union or enum specifier,
    /// including forward declarations, which name a type without defining it.
    declared: HashSet<String>,
    /// How many specifiers with a body each name has. More than one leaves a
    /// bare-name reference ambiguous.
    definition_sites: HashMap<String, usize>,
}

impl ProvenClosure {
    fn resolve(&self, context: &CppCompileContext, name: &str) -> NameResolution {
        if context.defined_macros.contains(name) {
            return NameResolution::CommandLineMacro;
        }
        if !self.declared.contains(name) {
            return NameResolution::Absent;
        }
        NameResolution::Declared {
            definition_sites: self.definition_sites.get(name).copied().unwrap_or(0),
        }
    }
}

fn parse_cpp_tree(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("the linked tree-sitter-cpp grammar matches this tree-sitter version");
    // Parsing returns `None` only for a cancelled or timed-out parse, and this
    // pass sets neither.
    parser.parse(source, None).expect("uncancelled C++ parse")
}

fn has_parse_errors(root: Node<'_>) -> bool {
    let mut errors = Vec::new();
    collect_parse_errors(root, &mut errors);
    !errors.is_empty()
}

/// Walk the `#include` closure of one compile configuration, collecting every
/// type name it introduces, or state why the closure cannot be reproduced.
///
/// The walk uses an explicit stack for both the file queue and the node walk,
/// so neither a deep include chain nor a deeply nested AST recurses.
fn prove_include_closure(
    source_file: &ProjectFile,
    source: &str,
    context: &CppCompileContext,
) -> Result<ProvenClosure, SemanticDiagnosticIncompleteReason> {
    // A forced include or a system root puts headers in front of this file that
    // the closure below cannot read, so the closure would not be the one the
    // compiler sees.
    if let Some(forced) = context.forced_includes.first() {
        return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
            detail: format!(
                "the compile command forces `-include {}`, whose declarations this pass cannot read",
                forced.display()
            ),
        });
    }
    if let Some(root) = context.system_include_roots.first() {
        return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
            detail: format!(
                "the compile command adds system include root `{}`, whose declarations this pass cannot read",
                root.display()
            ),
        });
    }

    let mut closure = ProvenClosure::default();
    let mut visited = HashSet::default();
    let mut pending = vec![(source_file.clone(), source.to_string())];
    while let Some((file, source)) = pending.pop() {
        if !visited.insert(file.abs_path()) {
            continue;
        }
        let tree = parse_cpp_tree(&source);
        if has_parse_errors(tree.root_node()) {
            debug_assert_ne!(
                file.abs_path(),
                source_file.abs_path(),
                "the entry file's parse errors are reported before the closure walk starts"
            );
            return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                detail: format!(
                    "included header `{}` has parse errors",
                    rel_path_string(&file)
                ),
            });
        }
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "preproc_include" => {
                    let Some(include) = quoted_include_path(node, &source) else {
                        // An angle-bracket or computed include names a header
                        // the build supplies and nothing here indexes.
                        return Err(
                            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                                boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                            },
                        );
                    };
                    let header = resolve_project_header(&file, &include, context)?;
                    let Ok(header_source) = header.read_to_string() else {
                        return Err(
                            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                                boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                            },
                        );
                    };
                    pending.push((header, header_source));
                }
                "preproc_def" | "preproc_function_def" => {
                    // A macro can spell, rename or generate a type name. This
                    // pass does not expand macros, so its view of the closure
                    // would be a guess.
                    let name = node
                        .child_by_field_name("name")
                        .map(|name| node_text(name, &source))
                        .unwrap_or_default();
                    return Err(
                        SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
                            detail: format!(
                                "`#define {name}` in `{}` can generate type names this pass does not expand",
                                rel_path_string(&file)
                            ),
                        },
                    );
                }
                "preproc_if" | "preproc_ifdef" | "preproc_ifndef" | "preproc_elif"
                | "preproc_else" => {
                    // Which declarations survive depends on preprocessor state
                    // this pass does not evaluate. Include guards are the
                    // common benign case and are still refused: recognizing one
                    // means proving it guards the whole file and nothing else.
                    return Err(SemanticDiagnosticIncompleteReason::DynamicBehavior {
                        detail: format!(
                            "conditional compilation `{}` in `{}` selects declarations this pass does not evaluate",
                            directive_keyword(node, &source),
                            rel_path_string(&file)
                        ),
                    });
                }
                kind if kind.starts_with("preproc_") => {
                    // Closed by default: an unclassified directive is refused
                    // rather than walked past, so a grammar that grows a new
                    // one cannot silently weaken the proof.
                    return Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
                        detail: format!(
                            "unsupported preprocessor directive `{}` in `{}`",
                            directive_keyword(node, &source),
                            rel_path_string(&file)
                        ),
                    });
                }
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                    if let Some(name) = declared_type_name(node, &source) {
                        if node.child_by_field_name("body").is_some() {
                            *closure.definition_sites.entry(name.clone()).or_default() += 1;
                        }
                        closure.declared.insert(name);
                    }
                    push_named_children(&mut stack, node);
                }
                "type_definition" | "alias_declaration" => {
                    // `typedef int Meters;` and `using Meters = int;` introduce
                    // a type name as surely as a struct does.
                    for name in alias_type_names(node, &source) {
                        closure.declared.insert(name);
                    }
                    push_named_children(&mut stack, node);
                }
                _ => push_named_children(&mut stack, node),
            }
        }
    }
    Ok(closure)
}

fn declared_type_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "type_identifier" | "identifier"))
    })?;
    let name = node_text(name, source).trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// The type names a `typedef` or a `using` alias binds.
///
/// A single `typedef` can bind several names at once (`typedef int A, B;`), so
/// this reads every declarator the node carries rather than just the first.
fn alias_type_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack: Vec<Node<'_>> = node
        .child_by_field_name("name")
        .into_iter()
        .chain({
            let mut cursor = node.walk();
            node.children_by_field_name("declarator", &mut cursor)
                .collect::<Vec<_>>()
        })
        .collect();
    // A declarator wraps the bound name in pointer, array and function layers;
    // the name is the `type_identifier` at the bottom of that chain.
    while let Some(current) = stack.pop() {
        if current.kind() == "type_identifier" {
            let name = node_text(current, source).trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
            continue;
        }
        push_named_children(&mut stack, current);
    }
    names
}

/// The directive keyword that opens a preprocessor node, read from the tree.
fn directive_keyword(node: Node<'_>, source: &str) -> String {
    node.child(0)
        .map(|token| node_text(token, source).trim().to_string())
        .filter(|token| !token.is_empty())
        .unwrap_or_else(|| node.kind().to_string())
}

fn quoted_include_path(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let literal = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "string_literal")?;
    let text = node_text(literal, source);
    text.strip_prefix('"')?
        .strip_suffix('"')
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_project_header(
    source_file: &ProjectFile,
    include: &str,
    context: &CppCompileContext,
) -> Result<ProjectFile, SemanticDiagnosticIncompleteReason> {
    let mut candidates = HashSet::default();
    if let Some(source_parent) = source_file.abs_path().parent().map(Path::to_path_buf) {
        for root in
            std::iter::once(source_parent).chain(context.project_include_roots.iter().cloned())
        {
            let candidate = root.join(include);
            if candidate.is_file() && candidate.starts_with(source_file.root()) {
                candidates.insert(candidate);
            }
        }
    }
    match candidates.len() {
        // The build declares the header; no project file supplies it, so its
        // declarations exist somewhere nothing here has indexed.
        0 => Err(
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalDeclaredUnindexed,
            },
        ),
        1 => Ok(ProjectFile::new(
            source_file.root().to_path_buf(),
            candidates
                .into_iter()
                .next()
                .expect("one candidate")
                .strip_prefix(source_file.root())
                .expect("candidate inside project")
                .to_path_buf(),
        )),
        // Several include roots supply the same name. Picking one would mean
        // reimplementing the compiler's search order.
        _ => Err(SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
            detail: format!(
                "`#include \"{include}\"` matches more than one project header on the include path"
            ),
        }),
    }
}

fn is_plain_type_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(
        parent.kind(),
        "declaration" | "type_descriptor" | "sized_type_specifier"
    ) {
        return false;
    }
    let mut current = parent;
    while let Some(ancestor) = current.parent() {
        if matches!(
            ancestor.kind(),
            "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "template_declaration"
                | "template_parameter_list"
                | "template_type"
                | "qualified_identifier"
                | "scoped_type_identifier"
        ) {
            return false;
        }
        current = ancestor;
    }
    true
}

fn push_named_children<'tree>(stack: &mut Vec<Node<'tree>>, node: Node<'tree>) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    stack.extend(children.into_iter().rev());
}
