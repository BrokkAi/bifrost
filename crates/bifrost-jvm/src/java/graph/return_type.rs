use super::JavaGraphSource;
use super::resolver::java_callable_arity;
use crate::java::graph_support::{JavaSource, resolve_java_usage_type_name};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome,
};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Mutex;
use tree_sitter::{Node, Parser};

pub const METHOD_RECEIVER_CHAIN_LIMIT: usize = 64;
pub const METHOD_RECEIVER_CHAIN_LIMIT_NAME: &str = "java_method_receiver_chain_depth";

/// Identifies one method declaration across the whole workspace. The declaring
/// file is part of the key because one fully qualified name can be declared in
/// more than one file; the signature separates overloads.
#[derive(PartialEq, Eq, Hash)]
pub struct MethodReturnCacheKey {
    pub source: ProjectFile,
    pub fq_name: String,
    pub signature: Option<String>,
}

/// Identifies one method declaration inside a single already-selected file, so
/// only the overload has to be distinguished.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FileReturnCacheKey {
    pub fq_name: String,
    pub signature: Option<String>,
}

pub type MethodReturnCache = Mutex<HashMap<MethodReturnCacheKey, ReceiverAnalysisOutcome<String>>>;
pub type MethodAnonymousReturnCache =
    Mutex<HashMap<MethodReturnCacheKey, ReceiverAnalysisOutcome<String>>>;
pub type FileReturnCache = Mutex<HashMap<ProjectFile, JavaFileReturnFacts>>;

#[derive(Clone, Default)]
pub struct JavaFileReturnFacts {
    declared_types: HashMap<FileReturnCacheKey, ReceiverAnalysisOutcome<String>>,
    anonymous_return_types: HashMap<FileReturnCacheKey, ReceiverAnalysisOutcome<String>>,
}

pub trait JavaReturnTypeContext {
    fn java(&self) -> &dyn JavaSource;
    fn file(&self) -> &ProjectFile;
    fn source(&self) -> &str;
    fn root(&self) -> Node<'_>;
    fn method_return_cache(&self) -> &MethodReturnCache;
    fn method_anonymous_return_cache(&self) -> &MethodAnonymousReturnCache;
    fn file_return_cache(&self) -> &FileReturnCache;
}

pub fn method_return_type_for_owner_fqns<'a, C, I>(
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

pub fn method_return_type_for_owner_fqn<C>(
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
        .usage_definitions()
        .fqn(&fqn)
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
    let cache_key = MethodReturnCacheKey {
        source: method.source().clone(),
        fq_name: method.fq_name(),
        signature: method.signature().map(str::to_string),
    };
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
    java_file_return_facts(ctx, method.source())
        .declared_types
        .get(&FileReturnCacheKey {
            fq_name: method.fq_name(),
            signature: method.signature().map(str::to_string),
        })
        .cloned()
        .unwrap_or(ReceiverAnalysisOutcome::Unknown)
}

pub fn method_anonymous_return_type_for_owner_fqn<C>(
    owner: &str,
    name: &str,
    arity: usize,
    ctx: &C,
) -> Option<ReceiverAnalysisOutcome<String>>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let fqn = format!("{owner}.{name}");
    let units = ctx
        .java()
        .usage_definitions()
        .fqn(&fqn)
        .iter()
        .filter(|unit| unit.is_function() && java_callable_arity(ctx.java(), unit).accepts(arity))
        .cloned()
        .collect::<Vec<_>>();
    (!units.is_empty()).then(|| {
        merge_receiver_type_outcomes(
            units
                .iter()
                .map(|unit| method_unit_anonymous_return_type(unit, ctx)),
        )
    })
}

fn method_unit_anonymous_return_type<C>(
    method: &CodeUnit,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let cache_key = MethodReturnCacheKey {
        source: method.source().clone(),
        fq_name: method.fq_name(),
        signature: method.signature().map(str::to_string),
    };
    if let Some(cached) = ctx
        .method_anonymous_return_cache()
        .lock()
        .expect("java anonymous return cache poisoned")
        .get(&cache_key)
        .cloned()
    {
        return cached;
    }
    let outcome = method_unit_anonymous_return_type_uncached(method, ctx);
    ctx.method_anonymous_return_cache()
        .lock()
        .expect("java anonymous return cache poisoned")
        .insert(cache_key, outcome.clone());
    outcome
}

fn method_unit_anonymous_return_type_uncached<C>(
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
        return method_declaration_covering(ctx.root(), &range)
            .map(|declaration| {
                method_declaration_anonymous_return_type(
                    ctx.java(),
                    ctx.file(),
                    ctx.source(),
                    declaration,
                    method,
                )
            })
            .unwrap_or(ReceiverAnalysisOutcome::Unknown);
    }
    java_file_return_facts(ctx, method.source())
        .anonymous_return_types
        .get(&FileReturnCacheKey {
            fq_name: method.fq_name(),
            signature: method.signature().map(str::to_string),
        })
        .cloned()
        .unwrap_or(ReceiverAnalysisOutcome::Unknown)
}

fn java_file_return_facts<C>(ctx: &C, file: &ProjectFile) -> JavaFileReturnFacts
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

    let index = build_java_file_return_facts(ctx, file);
    ctx.file_return_cache()
        .lock()
        .expect("java file return cache poisoned")
        .insert(file.clone(), index.clone());
    index
}

fn build_java_file_return_facts<C>(ctx: &C, file: &ProjectFile) -> JavaFileReturnFacts
where
    C: JavaReturnTypeContext + ?Sized,
{
    let Ok(source) = file.read_to_string() else {
        return JavaFileReturnFacts::default();
    };
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return JavaFileReturnFacts::default();
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return JavaFileReturnFacts::default();
    };
    let mut facts = JavaFileReturnFacts::default();
    for unit in ctx
        .java()
        .declarations(file)
        .into_iter()
        .filter(|unit| unit.is_function())
    {
        let key = FileReturnCacheKey {
            fq_name: unit.fq_name(),
            signature: unit.signature().map(str::to_string),
        };
        let declaration = ctx
            .java()
            .ranges(&unit)
            .first()
            .copied()
            .and_then(|range| method_declaration_covering(tree.root_node(), &range));
        let declared_type = declaration
            .and_then(|method| method.child_by_field_name("type"))
            .and_then(|type_node| {
                java_declared_type_fqn(ctx.java(), file, &source, type_node, &unit)
            })
            .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown);
        let anonymous_return_type = declaration
            .map(|method| {
                method_declaration_anonymous_return_type(ctx.java(), file, &source, method, &unit)
            })
            .unwrap_or(ReceiverAnalysisOutcome::Unknown);
        facts.declared_types.insert(key.clone(), declared_type);
        facts
            .anonymous_return_types
            .insert(key, anonymous_return_type);
    }
    facts
}

fn java_declared_type_fqn(
    java: &dyn JavaSource,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    declaration: &CodeUnit,
) -> Option<String> {
    let components = java_type_name_components(type_node, source)?;
    match java_lexical_type_from_declaration(java, declaration, &components) {
        LexicalTypeResolution::Resolved(unit) => Some(unit.fq_name()),
        LexicalTypeResolution::Blocked => None,
        LexicalTypeResolution::NotFound => {
            resolve_java_usage_type_name(java, file, &components.join("."))
                .map(|unit| unit.fq_name())
        }
    }
}

pub fn java_type_name_from_node(type_node: Node<'_>, source: &str) -> Option<String> {
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

pub fn is_java_nominal_type_node(kind: &str) -> bool {
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

pub enum LexicalTypeResolution {
    Resolved(CodeUnit),
    NotFound,
    Blocked,
}

pub fn java_lexical_type_from_node(
    java: &dyn JavaSource,
    graph: &JavaGraphSource<'_>,
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
    let Some(declaration) = graph.index.enclosing_code_unit(file, &range) else {
        return LexicalTypeResolution::NotFound;
    };
    java_lexical_type_from_declaration(java, &declaration, &components)
}

fn java_lexical_type_from_declaration(
    java: &dyn JavaSource,
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
    let mut visited = brokk_bifrost_core::hash::HashSet::default();
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
    java: &dyn JavaSource,
    fqn: &str,
    file: &ProjectFile,
) -> Result<Option<CodeUnit>, ()> {
    let units = java.usage_definitions().fqn(fqn);
    let mut candidates = units
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

fn method_declaration_covering<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        if node.kind() == "method_declaration" {
            return Some(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn method_declaration_anonymous_return_type(
    java: &dyn JavaSource,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    declaration: &CodeUnit,
) -> ReceiverAnalysisOutcome<String> {
    let Some(body) = method.child_by_field_name("body") else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let mut return_types = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.kind() == "return_statement" {
            let Some(value) = node
                .child_by_field_name("value")
                .or_else(|| node.named_child(0))
            else {
                return ReceiverAnalysisOutcome::Unknown;
            };
            if value.kind() != "object_creation_expression" || !has_anonymous_class_body(value) {
                return ReceiverAnalysisOutcome::Unknown;
            }
            let Some(type_node) = value.child_by_field_name("type") else {
                return ReceiverAnalysisOutcome::Unknown;
            };
            let Some(fqn) = java_declared_type_fqn(java, file, source, type_node, declaration)
            else {
                return ReceiverAnalysisOutcome::Unknown;
            };
            return_types.push(fqn);
            continue;
        }
        if matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "lambda_expression"
        ) {
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    if return_types.is_empty() {
        ReceiverAnalysisOutcome::Unknown
    } else {
        ReceiverAnalysisOutcome::Precise(return_types)
    }
}

fn has_anonymous_class_body(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "class_body")
}

pub fn merge_receiver_type_outcomes(
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
