use super::resolver::java_callable_arity;
use crate::analyzer::usages::common::node_text;
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, ProjectFile, Range};
use crate::hash::HashMap;
use std::sync::Mutex;
use tree_sitter::{Node, Parser};

pub(super) const METHOD_RECEIVER_CHAIN_LIMIT: usize = 64;
pub(super) const METHOD_RECEIVER_CHAIN_LIMIT_NAME: &str = "java_method_receiver_chain_depth";

pub(super) type MethodReturnCacheKey = (ProjectFile, String, Option<String>);
pub(super) type MethodReturnCache =
    Mutex<HashMap<MethodReturnCacheKey, ReceiverAnalysisOutcome<String>>>;
pub(super) type FileReturnCacheKey = (String, Option<String>);
pub(super) type FileReturnCache =
    Mutex<HashMap<ProjectFile, HashMap<FileReturnCacheKey, ReceiverAnalysisOutcome<String>>>>;

pub(super) trait JavaReturnTypeContext {
    fn java(&self) -> &JavaAnalyzer;
    fn file(&self) -> &ProjectFile;
    fn source(&self) -> &str;
    fn root(&self) -> Node<'_>;
    fn method_return_cache(&self) -> &MethodReturnCache;
    fn file_return_cache(&self) -> &FileReturnCache;
}

pub(super) fn method_return_type_for_owner_fqns<'a, C, I>(
    owners: I,
    name: &str,
    arity: usize,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
    I: IntoIterator<Item = &'a str>,
{
    merge_receiver_type_outcomes(
        owners
            .into_iter()
            .map(|owner| method_return_type_for_owner_fqn(owner, name, arity, ctx)),
    )
}

pub(super) fn method_return_type_for_owner_fqn<C>(
    owner: &str,
    name: &str,
    arity: usize,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let fqn = format!("{owner}.{name}");
    let units = ctx
        .java()
        .global_usage_definition_index()
        .by_fqn(&fqn)
        .iter()
        .filter(|unit| unit.is_function() && java_callable_arity(ctx.java(), unit).accepts(arity))
        .cloned()
        .collect::<Vec<_>>();
    if units.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    merge_receiver_type_outcomes(
        units
            .into_iter()
            .map(|unit| method_unit_declared_return_type(&unit, ctx)),
    )
}

fn method_unit_declared_return_type<C>(
    method: &CodeUnit,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let cache_key = (
        method.source().clone(),
        method.fq_name(),
        method.signature().map(str::to_string),
    );
    if let Some(cached) = ctx
        .method_return_cache()
        .lock()
        .expect("java return type cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        return cached;
    }
    let outcome = method_unit_declared_return_type_uncached(method, ctx);
    ctx.method_return_cache()
        .lock()
        .expect("java return type cache poisoned")
        .insert(cache_key, outcome.clone());
    outcome
}

fn method_unit_declared_return_type_uncached<C>(
    method: &CodeUnit,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let Some(range) = ctx.java().ranges(method).first().copied() else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    if method.source() == ctx.file() {
        return java_return_type_node_covering(ctx.root(), &range)
            .and_then(|type_node| {
                java_declared_type_fqn(ctx.java(), ctx.file(), ctx.source(), type_node, method)
            })
            .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown);
    }
    java_file_return_type_index(ctx, method.source())
        .get(&(method.fq_name(), method.signature().map(str::to_string)))
        .cloned()
        .unwrap_or(ReceiverAnalysisOutcome::Unknown)
}

fn java_file_return_type_index<C>(
    ctx: &C,
    file: &ProjectFile,
) -> HashMap<FileReturnCacheKey, ReceiverAnalysisOutcome<String>>
where
    C: JavaReturnTypeContext + ?Sized,
{
    if let Some(cached) = ctx
        .file_return_cache()
        .lock()
        .expect("java file return cache poisoned")
        .get(file)
        .cloned()
    {
        return cached;
    }

    let index = build_java_file_return_type_index(ctx, file);
    ctx.file_return_cache()
        .lock()
        .expect("java file return cache poisoned")
        .insert(file.clone(), index.clone());
    index
}

fn build_java_file_return_type_index<C>(
    ctx: &C,
    file: &ProjectFile,
) -> HashMap<FileReturnCacheKey, ReceiverAnalysisOutcome<String>>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let Ok(source) = file.read_to_string() else {
        return HashMap::default();
    };
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return HashMap::default();
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return HashMap::default();
    };
    ctx.java()
        .declarations(file)
        .into_iter()
        .filter(|unit| unit.is_function())
        .map(|unit| {
            let outcome = ctx
                .java()
                .ranges(&unit)
                .first()
                .copied()
                .and_then(|range| java_return_type_node_covering(tree.root_node(), &range))
                .and_then(|type_node| {
                    java_declared_type_fqn(ctx.java(), file, &source, type_node, &unit)
                })
                .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
                .unwrap_or(ReceiverAnalysisOutcome::Unknown);
            (
                (unit.fq_name(), unit.signature().map(str::to_string)),
                outcome,
            )
        })
        .collect()
}

fn java_declared_type_fqn(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    declaration: &CodeUnit,
) -> Option<String> {
    let components = java_type_name_components(type_node, source)?;
    match java_lexical_type_from_declaration(java, declaration, &components) {
        LexicalTypeResolution::Resolved(unit) => Some(unit.fq_name()),
        LexicalTypeResolution::Blocked => None,
        LexicalTypeResolution::NotFound => java
            .resolve_usage_type_name(file, &components.join("."))
            .map(|unit| unit.fq_name()),
    }
}

pub(super) fn java_type_name_from_node(type_node: Node<'_>, source: &str) -> Option<String> {
    java_type_name_components(type_node, source).map(|components| components.join("."))
}

fn java_type_name_components(type_node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut components = Vec::new();
    let mut stack = vec![type_node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" | "type_identifier" => {
                let component = node_text(node, source);
                if component.is_empty() {
                    return None;
                }
                components.push(component.to_string());
            }
            "array_type" => stack.push(node.child_by_field_name("element")?),
            "annotated_type" | "generic_type" => {
                let mut cursor = node.walk();
                let nominal = node
                    .named_children(&mut cursor)
                    .find(|child| is_java_nominal_type_node(child.kind()))?;
                stack.push(nominal);
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = node.walk();
                let nominal_children = node
                    .named_children(&mut cursor)
                    .filter(|child| is_java_nominal_type_node(child.kind()))
                    .collect::<Vec<_>>();
                if nominal_children.is_empty() {
                    return None;
                }
                stack.extend(nominal_children.into_iter().rev());
            }
            _ => return None,
        }
    }
    (!components.is_empty()).then_some(components)
}

fn is_java_nominal_type_node(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "scoped_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "array_type"
            | "annotated_type"
    )
}

pub(super) enum LexicalTypeResolution {
    Resolved(CodeUnit),
    NotFound,
    Blocked,
}

pub(super) fn java_lexical_type_from_node(
    java: &JavaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> LexicalTypeResolution {
    let Some(components) = java_type_name_components(node, source) else {
        return LexicalTypeResolution::Blocked;
    };
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let Some(declaration) = analyzer.enclosing_code_unit(file, &range) else {
        return LexicalTypeResolution::NotFound;
    };
    java_lexical_type_from_declaration(java, &declaration, &components)
}

fn java_lexical_type_from_declaration(
    java: &JavaAnalyzer,
    declaration: &CodeUnit,
    components: &[String],
) -> LexicalTypeResolution {
    let Some(first_component) = components.first() else {
        return LexicalTypeResolution::NotFound;
    };
    let mut scope = declaration
        .is_class()
        .then(|| declaration.clone())
        .or_else(|| java.parent_of(declaration));
    let mut visited = crate::hash::HashSet::default();
    while let Some(owner) = scope {
        if !visited.insert(owner.clone()) {
            return LexicalTypeResolution::Blocked;
        }
        scope = java.parent_of(&owner);
        if !owner.is_class() {
            continue;
        }

        let mut first_binding = (owner.identifier() == first_component).then(|| owner.clone());
        let nested_fqn = format!("{}.{}", owner.fq_name(), first_component);
        match unique_java_class_by_fqn_in_file(java, &nested_fqn, owner.source()) {
            Ok(Some(nested)) if first_binding.as_ref().is_some_and(|bound| bound != &nested) => {
                return LexicalTypeResolution::Blocked;
            }
            Ok(Some(nested)) => first_binding = Some(nested),
            Ok(None) => {}
            Err(()) => return LexicalTypeResolution::Blocked,
        }

        let Some(first_binding) = first_binding else {
            continue;
        };
        if components.len() == 1 {
            return LexicalTypeResolution::Resolved(first_binding);
        }
        let qualified_fqn = format!("{}.{}", first_binding.fq_name(), components[1..].join("."));
        return match unique_java_class_by_fqn_in_file(java, &qualified_fqn, owner.source()) {
            Ok(Some(unit)) => LexicalTypeResolution::Resolved(unit),
            Ok(None) | Err(()) => LexicalTypeResolution::Blocked,
        };
    }
    LexicalTypeResolution::NotFound
}

fn unique_java_class_by_fqn_in_file(
    java: &JavaAnalyzer,
    fqn: &str,
    file: &ProjectFile,
) -> Result<Option<CodeUnit>, ()> {
    let mut candidates = java
        .global_usage_definition_index()
        .by_fqn(fqn)
        .iter()
        .filter(|unit| unit.is_class() && unit.source() == file);
    let Some(first) = candidates.next() else {
        return Ok(None);
    };
    if candidates.any(|candidate| candidate != first) {
        return Err(());
    }
    Ok(Some(first.clone()))
}

fn java_return_type_node_covering<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    let mut result = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        if node.kind() == "method_declaration"
            && let Some(type_node) = node.child_by_field_name("type")
        {
            result = Some(type_node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    result
}

pub(super) fn merge_receiver_type_outcomes(
    outcomes: impl IntoIterator<Item = ReceiverAnalysisOutcome<String>>,
) -> ReceiverAnalysisOutcome<String> {
    ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, ReceiverAnalysisBudget::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn nominal_type_name_uses_structured_java_wrappers() {
        let source = r#"
class Sample {
    Target[] array() { return null; }
    Box<Target> generic() { return null; }
    pkg.Outer<String>.Inner scoped() { return null; }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java parser language");
        let tree = parser.parse(source, None).expect("parsed Java fixture");
        let mut actual = BTreeMap::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_declaration" {
                let name_node = node.child_by_field_name("name").expect("method name");
                let type_node = node.child_by_field_name("type").expect("method type");
                actual.insert(
                    node_text(name_node, source).to_string(),
                    java_type_name_from_node(type_node, source).expect("nominal type name"),
                );
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }

        assert_eq!(
            BTreeMap::from([
                ("array".to_string(), "Target".to_string()),
                ("generic".to_string(), "Box".to_string()),
                ("scoped".to_string(), "pkg.Outer.Inner".to_string()),
            ]),
            actual
        );
    }
}
