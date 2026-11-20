//! Which exceptions a Java catch clause receives.
//!
//! A checked exception is a `Throwable` that is not a `RuntimeException` or
//! an `Error`. A method or constructor may throw one only if its `throws`
//! clause declares it (JLS 11.2), and an override cannot declare more than the
//! method it overrides (JLS 8.4.8.3). So a call whose statically resolved
//! callee declares nothing cannot deliver a checked exception, and a catch
//! clause whose one type is a checked exception class cannot receive anything
//! that call throws.
//!
//! Every exception is an instance of `java.lang.Throwable` (JLS 11.1.1), so
//! a `try` with a catch clause for that class lets no exception thrown in its
//! body leave the statement without entering a handler (JLS 14.20.1).

use std::ops::Range;
use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::java::JavaAnalyzer;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_call_target_batch_with_source;

use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source_traced;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_analysis::analyzer::semantic::ControlEdgeId;

use brokk_bifrost_analysis::analyzer::semantic::ControlEdgeKind;

use brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics;

use brokk_bifrost_analysis::analyzer::semantic::ProgramPoint;

use brokk_bifrost_analysis::analyzer::semantic::SourceMappingKind;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::source_span_for_node;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

/// Each point of `semantics` with the successor shape of a `try` statement's
/// handler dispatcher, and its edge on which no catch clause matched.
///
/// Lowering gives a `try` with catch clauses one dispatcher: a `SwitchCase`
/// edge to each catch body and one `Exceptional` edge that rethrows out of
/// the statement. The shape alone does not prove the point is a dispatcher;
/// [`uncaught_edges_of_total_handlers`] checks its syntax.
fn handler_dispatcher_candidates(
    semantics: &ProcedureSemantics,
) -> impl Iterator<Item = (&ProgramPoint, ControlEdgeId)> + '_ {
    semantics.points().iter().filter_map(|point| {
        let mut enters_handler = false;
        let mut uncaught = None;
        for (id, edge) in semantics.successor_edges(point.id) {
            match edge.kind {
                ControlEdgeKind::SwitchCase => enters_handler = true,
                ControlEdgeKind::Exceptional if uncaught.is_none() => uncaught = Some(id),
                // A dispatcher has one uncaught edge; a second means another shape.
                ControlEdgeKind::Exceptional => return None,
                _ => {}
            }
        }
        uncaught
            .filter(|_| enters_handler)
            .map(|uncaught| (point, uncaught))
    })
}

/// Whether [`uncaught_edges_of_total_handlers`] has a point to examine.
pub(crate) fn has_handler_dispatcher_candidate(semantics: &ProcedureSemantics) -> bool {
    handler_dispatcher_candidates(semantics).next().is_some()
}

/// The uncaught-exception edge of every `try` statement in `semantics` that
/// has a catch clause for `java.lang.Throwable`, in ascending order.
///
/// `syntax` is the exact tree of `file` the procedure was lowered from. A
/// dispatcher whose syntax is not an exact `try` statement, and a catch type
/// that does not provably resolve to `java.lang.Throwable`, keep their edge.
/// A catch clause for `Exception` keeps it too, because an `Error` passes it.
pub(crate) fn uncaught_edges_of_total_handlers(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    semantics: &ProcedureSemantics,
) -> Vec<ControlEdgeId> {
    let root = syntax.tree().root_node();
    let mut source = None;
    let mut infeasible = Vec::new();
    for (point, uncaught) in handler_dispatcher_candidates(semantics) {
        let Some(mapping) = semantics.source_mapping(point.source) else {
            continue;
        };
        if mapping.kind != SourceMappingKind::Exact {
            continue;
        }
        let span = mapping.locator.anchor().span();
        let Some(statement) = root
            .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        else {
            continue;
        };
        if source_span_for_node(statement) != span
            || !matches!(
                statement.kind(),
                "try_statement" | "try_with_resources_statement"
            )
        {
            continue;
        }
        if catches_every_throwable(analyzer, file, syntax, &mut source, statement) {
            infeasible.push(uncaught);
        }
    }
    infeasible.sort_unstable();
    infeasible
}

/// Whether one catch clause of the `try` statement `statement` names
/// `java.lang.Throwable`, alone or as a multi-catch alternative.
fn catches_every_throwable(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    source: &mut Option<Arc<str>>,
    statement: Node<'_>,
) -> bool {
    let mut cursor = statement.walk();
    let mut written_types = Vec::new();
    for clause in statement.named_children(&mut cursor) {
        if clause.kind() != "catch_clause" {
            continue;
        }
        let mut cursor = clause.walk();
        for parameter in clause.named_children(&mut cursor) {
            if parameter.kind() != "catch_formal_parameter" {
                continue;
            }
            let mut cursor = parameter.walk();
            for catch_type in parameter.named_children(&mut cursor) {
                if catch_type.kind() != "catch_type" {
                    continue;
                }
                let mut cursor = catch_type.walk();
                written_types.extend(
                    catch_type
                        .named_children(&mut cursor)
                        .filter(|child| !child.is_extra()),
                );
            }
        }
    }
    written_types.into_iter().any(|written| {
        // Java has no import alias, so only a type whose last identifier is
        // `Throwable` can resolve to `java.lang.Throwable`. The name selects
        // which types to resolve; the resolver decides what they are.
        let name = match written.kind() {
            "type_identifier" => Some(written),
            "scoped_type_identifier" => {
                let mut cursor = written.walk();
                written.named_children(&mut cursor).last()
            }
            _ => None,
        };
        if name.and_then(|name| syntax.source().get(name.byte_range())) != Some("Throwable") {
            return false;
        }
        let source = source.get_or_insert_with(|| Arc::from(syntax.source()));
        matches!(
            resolve_type_at(analyzer, file, source, written),
            TypeResolution::JavaLang("Throwable")
        )
    })
}

/// Whether the call whose source mapping spans `call` provably cannot throw an
/// exception the catch parameter whose name spans `catch_parameter` catches.
///
/// `source` is the exact text the spans index. Every step that is not proven
/// answers `false`, which keeps the binding: an unparsed or stale file, a
/// multi-type or unresolved catch type, a catch type that is not a proven
/// checked exception class, an unresolved or external callee, a callee with a
/// `throws` clause, and an anonymous class creation.
pub(crate) fn call_cannot_reach_catch_parameter(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    call: Range<usize>,
    catch_parameter: Range<usize>,
) -> bool {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return false;
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let Some(prepared) = java.inner().prepared_syntax(token, file) else {
        return false;
    };
    if prepared.source() != source.as_ref() {
        return false;
    }
    let root = prepared.tree().root_node();
    let Some(caught) = caught_class(analyzer, file, source, root, catch_parameter) else {
        return false;
    };
    is_checked_exception_class(analyzer, java, token, caught)
        && callee_declares_no_exception(analyzer, java, token, file, source, root, call)
}

/// The workspace class a single-type catch parameter names.
fn caught_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    root: Node<'_>,
    catch_parameter: Range<usize>,
) -> Option<CodeUnit> {
    let name = root.named_descendant_for_byte_range(catch_parameter.start, catch_parameter.end)?;
    let parameter = name.parent()?;
    if parameter.kind() != "catch_formal_parameter"
        || parameter.child_by_field_name("name")?.byte_range() != catch_parameter
    {
        return None;
    }
    let mut cursor = parameter.walk();
    let catch_type = parameter
        .named_children(&mut cursor)
        .find(|child| child.kind() == "catch_type")?;
    let mut cursor = catch_type.walk();
    let types = catch_type
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>();
    let [caught] = types.as_slice() else {
        return None;
    };
    match resolve_type_at(analyzer, file, source, *caught) {
        TypeResolution::Class(unit) => Some(unit),
        TypeResolution::JavaLang(_) | TypeResolution::Unknown => None,
    }
}

/// Whether `class` descends from `java.lang.Exception` or directly from
/// `java.lang.Throwable` without passing `RuntimeException` or `Error`.
///
/// The walk follows each workspace class's `superclass` in that class's own
/// file. An exception class cannot be generic (JLS 8.1.2), so a generic or
/// otherwise unresolved superclass leaves the answer unproven.
fn is_checked_exception_class(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    class: CodeUnit,
) -> bool {
    let mut visited = HashSet::default();
    let mut current = class;
    loop {
        if !visited.insert(current.clone()) {
            return false;
        }
        let Some(prepared) = java.inner().prepared_syntax(token, current.source()) else {
            return false;
        };
        let Some(declaration) = prepared.declaration_node(&current) else {
            return false;
        };
        if declaration.kind() != "class_declaration" {
            return false;
        }
        let Some(superclass) = declaration.child_by_field_name("superclass") else {
            return false;
        };
        let Some(written) = superclass.named_child(0) else {
            return false;
        };
        let source: Arc<str> = Arc::from(prepared.source());
        match resolve_type_at(analyzer, current.source(), &source, written) {
            TypeResolution::Class(unit) => current = unit,
            TypeResolution::JavaLang(name) => {
                return matches!(name, "Exception" | "Throwable");
            }
            TypeResolution::Unknown => return false,
        }
    }
}

/// What one written type resolves to.
enum TypeResolution {
    /// A workspace class declaration.
    Class(CodeUnit),
    /// A `java.lang` throwable root, named by its simple name.
    JavaLang(&'static str),
    Unknown,
}

/// Resolve a written type through the same resolver "go to definition" uses,
/// so nested types in lexical scope and every import tier apply.
///
/// The resolver supplies source declarations or an indexed intrinsic boundary.
/// An absent or incomplete name is never evidence of a java.lang identity.
fn resolve_type_at(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    written: Node<'_>,
) -> TypeResolution {
    let outcome = resolve_definition_batch_with_source_traced(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(written.start_byte()),
            end_byte: Some(written.end_byte()),
        }],
        file.clone(),
        Arc::clone(source),
    )
    .into_iter()
    .next();
    let Some((outcome, trace)) = outcome else {
        return TypeResolution::Unknown;
    };
    match outcome.status {
        DefinitionLookupStatus::Resolved => match outcome.definitions.as_slice() {
            [unit] if unit.is_class() => TypeResolution::Class(unit.clone()),
            _ => TypeResolution::Unknown,
        },
        DefinitionLookupStatus::NoDefinition
        | DefinitionLookupStatus::UnresolvableImportBoundary => {
            use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCandidateRef;
            let mut selected = trace.selected();
            let Some(candidate) = selected.next() else {
                return TypeResolution::Unknown;
            };
            if selected.next().is_some() {
                return TypeResolution::Unknown;
            }
            match &candidate.candidate {
                TraceCandidateRef::Intrinsic { name } => match name.as_str() {
                    "java.lang.Exception" => TypeResolution::JavaLang("Exception"),
                    "java.lang.Throwable" => TypeResolution::JavaLang("Throwable"),
                    "java.lang.RuntimeException" => TypeResolution::JavaLang("RuntimeException"),
                    "java.lang.Error" => TypeResolution::JavaLang("Error"),
                    _ => TypeResolution::Unknown,
                },
                _ => TypeResolution::Unknown,
            }
        }
        _ => TypeResolution::Unknown,
    }
}

/// Whether every statically resolved target of the call spanning `call`
/// declares no `throws` clause.
///
/// A class with no constructor declaration gets a default constructor with no
/// `throws` clause (JLS 8.8.9), so `new C()` resolving to such a class declares
/// nothing. An anonymous class creation runs an initializer this check does
/// not read, so it stays unproven.
fn callee_declares_no_exception(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &Arc<str>,
    root: Node<'_>,
    call: Range<usize>,
) -> bool {
    let Some(mut node) = root.descendant_for_byte_range(call.start, call.end) else {
        return false;
    };
    while node.byte_range() != call
        || !matches!(
            node.kind(),
            "method_invocation" | "object_creation_expression"
        )
    {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.start_byte() < call.start || parent.end_byte() > call.end {
            return false;
        }
        node = parent;
    }
    let creation = node.kind() == "object_creation_expression";
    let mut cursor = node.walk();
    if creation
        && node
            .named_children(&mut cursor)
            .any(|child| child.kind() == "class_body")
    {
        return false;
    }
    let Some(focus) = node.child_by_field_name(if creation { "type" } else { "name" }) else {
        return false;
    };
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let lookup = resolve_call_target_batch_with_source(
        analyzer,
        token,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(focus.start_byte()),
            end_byte: Some(focus.end_byte()),
        }],
        file.clone(),
        Arc::clone(source),
        None,
    )
    .into_iter()
    .next();
    let Some(lookup) = lookup else {
        return false;
    };
    if lookup.outcome.status != DefinitionLookupStatus::Resolved
        || lookup.truncated
        || lookup.structure_unavailable
        || lookup.unproven_link_unit
        || lookup.outcome.definitions.is_empty()
    {
        return false;
    }
    lookup.outcome.definitions.iter().all(|target| {
        let Some(prepared) = java.inner().prepared_syntax(token, target.source()) else {
            return false;
        };
        let Some(declaration) = prepared.declaration_node(target) else {
            return false;
        };
        let mut cursor = declaration.walk();
        let mut children = declaration.named_children(&mut cursor);
        match declaration.kind() {
            "method_declaration" | "constructor_declaration" => {
                !children.any(|child| child.kind() == "throws")
            }
            "class_declaration" if creation && arguments.named_child_count() == 0 => {
                declaration.child_by_field_name("body").is_some_and(|body| {
                    let mut cursor = body.walk();
                    !body
                        .named_children(&mut cursor)
                        .any(|member| member.kind() == "constructor_declaration")
                })
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {

    use crate::analyzer::java::checked_exceptions::*;

    use brokk_bifrost_core::analyzer::model::Language;

    /// One `try` per case. Each catch parameter has a distinct name, and the
    /// call under test is the first statement of its `try` block. The
    /// analyzer does not check JLS 11.2.3, so a catch of a checked exception
    /// its `try` block never throws is still a readable fixture.
    const SOURCE: &str = r#"class App {
    static class FlowException extends Exception {}
    static class Deep extends FlowException {}
    static class Unchecked extends RuntimeException {}
    static class Remote extends Missing {}
    static class Plain {}
    static class Explicit { Explicit() throws FlowException {} }

    static int quiet() { return 1; }
    static int loud() throws FlowException { return 1; }

    void run() {
        try { quiet(); } catch (FlowException quietCaught) {}
        try { new Plain(); } catch (FlowException implicitCaught) {}
        try { loud(); } catch (FlowException loudCaught) {}
        try { new Explicit(); } catch (FlowException explicitCaught) {}
        try { quiet(); } catch (Exception broadCaught) {}
        try { quiet(); } catch (Unchecked uncheckedCaught) {}
        try { quiet(); } catch (Deep deepCaught) {}
        try { quiet(); } catch (Remote remoteCaught) {}
        try { new Plain() {}; } catch (FlowException anonymousCaught) {}
        try { quiet(); } catch (FlowException | Unchecked multiCaught) {}
    }
}
"#;

    fn cannot_reach(parameter: &str) -> bool {
        cannot_reach_in(SOURCE, parameter)
    }

    fn cannot_reach_in(source: &str, parameter: &str) -> bool {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let name_start = source
            .find(&format!(" {parameter})"))
            .expect("catch parameter in fixture")
            + 1;
        let call_start = source[..name_start].rfind("try { ").expect("try block") + "try { ".len();
        let call_end = call_start + source[call_start..].find(';').expect("call statement");
        call_cannot_reach_catch_parameter(
            workspace.analyzer(),
            &project.file("App.java"),
            &Arc::from(source),
            call_start..call_end,
            name_start..name_start + parameter.len(),
        )
    }

    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#2314: A resolved callee without throws was incorrectly allowed to reach checked catches"
    )]
    fn a_callee_without_throws_cannot_reach_a_checked_catch() {
        assert!(cannot_reach("quietCaught"));
        assert!(cannot_reach("deepCaught"));
    }

    #[test]
    #[hardwon(
        "#2314: An implicit default constructor was incorrectly treated as throwing a checked exception"
    )]
    fn an_implicit_default_constructor_cannot_reach_a_checked_catch() {
        assert!(cannot_reach("implicitCaught"));
    }

    #[test]
    #[hardwon(
        "#2314: Declared method and constructor throws clauses were ignored when retaining catch bindings"
    )]
    fn a_declared_throws_clause_keeps_the_binding() {
        assert!(!cannot_reach("loudCaught"));
        assert!(!cannot_reach("explicitCaught"));
    }

    #[test]
    #[hardwon(
        "#2314: Broad, unchecked, and multi-catch clauses were incorrectly treated as unreachable"
    )]
    fn a_catch_that_receives_unchecked_exceptions_keeps_the_binding() {
        assert!(!cannot_reach("broadCaught"));
        assert!(!cannot_reach("uncheckedCaught"));
        assert!(!cannot_reach("multiCaught"));
    }

    #[test]
    #[hardwon(
        "#2314: Unresolved exception ancestry and anonymous initializers incorrectly lost conservative catch bindings"
    )]
    fn unproven_shapes_keep_the_binding() {
        assert!(!cannot_reach("remoteCaught"));
        assert!(!cannot_reach("anonymousCaught"));
    }

    /// A bare `Exception` is `java.lang.Exception` only through the implicit
    /// `java.lang.*` import, which every other type scope shadows.
    #[test]
    #[hardwon(
        "#7006: release builds never proved a bare `Exception` was java.lang.Exception, so no catch binding was refuted"
    )]
    fn a_shadowable_exception_root_keeps_the_binding() {
        let shadowed = |prefix: &str, outer_supertype: &str| {
            format!(
                "{prefix}class App{outer_supertype} {{
    static class FlowException extends Exception {{}}
    static int quiet() {{ return 1; }}
    void run() {{
        try {{ quiet(); }} catch (FlowException shadowCaught) {{}}
    }}
}}
"
            )
        };
        assert!(cannot_reach_in(&shadowed("", ""), "shadowCaught"));
        // A member type inherited from an unindexed supertype may be named
        // `Exception`.
        assert!(!cannot_reach_in(
            &shadowed("", " extends Missing"),
            "shadowCaught"
        ));
        // An unindexed single-type or on-demand import may supply it.
        assert!(!cannot_reach_in(
            &shadowed("import com.acme.Exception;\n", ""),
            "shadowCaught"
        ));
        assert!(!cannot_reach_in(
            &shadowed("import com.acme.*;\n", ""),
            "shadowCaught"
        ));
    }
}
