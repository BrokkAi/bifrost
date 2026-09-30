//! Whether a Java call can throw an exception a catch clause catches.
//!
//! A checked exception is a `Throwable` that is not a `RuntimeException` or
//! an `Error`. A method or constructor may throw one only if its `throws`
//! clause declares it (JLS 11.2), and an override cannot declare more than the
//! method it overrides (JLS 8.4.8.3). So a call whose statically resolved
//! callee declares nothing cannot deliver a checked exception, and a catch
//! clause whose one type is a checked exception class cannot receive anything
//! that call throws.

use std::ops::Range;
use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::java::JavaAnalyzer;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_target_batch_with_source,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, IAnalyzer, ProjectFile, QueryScope, QueryToken, resolve_analyzer,
};
use crate::hash::HashSet;

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
/// The workspace does not index the JDK. Every compilation unit imports
/// `java.lang.*` on demand (JLS 7.5.5), so a bare throwable root name that no
/// workspace tier resolves is `java.lang`'s: another on-demand import
/// supplying the same simple name would make the name ambiguous, which is a
/// compile error. An import boundary or an ambiguity stays unknown.
fn resolve_type_at(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    written: Node<'_>,
) -> TypeResolution {
    let outcome = resolve_definition_batch_with_source(
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
    let Some(outcome) = outcome else {
        return TypeResolution::Unknown;
    };
    match outcome.status {
        DefinitionLookupStatus::Resolved => match outcome.definitions.as_slice() {
            [unit] if unit.is_class() => TypeResolution::Class(unit.clone()),
            _ => TypeResolution::Unknown,
        },
        DefinitionLookupStatus::NoDefinition if written.kind() == "type_identifier" => {
            match &source[written.byte_range()] {
                "Exception" => TypeResolution::JavaLang("Exception"),
                "Throwable" => TypeResolution::JavaLang("Throwable"),
                "RuntimeException" => TypeResolution::JavaLang("RuntimeException"),
                "Error" => TypeResolution::JavaLang("Error"),
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
    use super::*;
    use crate::analyzer::Language;

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
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let name_start = SOURCE
            .find(&format!(" {parameter})"))
            .expect("catch parameter in fixture")
            + 1;
        let call_start = SOURCE[..name_start].rfind("try { ").expect("try block") + "try { ".len();
        let call_end = call_start + SOURCE[call_start..].find(';').expect("call statement");
        call_cannot_reach_catch_parameter(
            workspace.analyzer(),
            &project.file("App.java"),
            &Arc::from(SOURCE),
            call_start..call_end,
            name_start..name_start + parameter.len(),
        )
    }

    #[test]
    fn a_callee_without_throws_cannot_reach_a_checked_catch() {
        assert!(cannot_reach("quietCaught"));
        assert!(cannot_reach("deepCaught"));
    }

    #[test]
    fn an_implicit_default_constructor_cannot_reach_a_checked_catch() {
        assert!(cannot_reach("implicitCaught"));
    }

    #[test]
    fn a_declared_throws_clause_keeps_the_binding() {
        assert!(!cannot_reach("loudCaught"));
        assert!(!cannot_reach("explicitCaught"));
    }

    #[test]
    fn a_catch_that_receives_unchecked_exceptions_keeps_the_binding() {
        assert!(!cannot_reach("broadCaught"));
        assert!(!cannot_reach("uncheckedCaught"));
        assert!(!cannot_reach("multiCaught"));
    }

    #[test]
    fn unproven_shapes_keep_the_binding() {
        assert!(!cannot_reach("remoteCaught"));
        assert!(!cannot_reach("anonymousCaught"));
    }
}
