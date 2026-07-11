use super::resolver::signature_arity;
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
    fn root(&self) -> Node<'_>;
    fn resolve_type_fqn(&self, node: Node<'_>) -> Option<String>;
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
        .definition_lookup_index()
        .by_fqn(&fqn)
        .iter()
        .filter(|unit| unit.is_function() && signature_arity(unit.signature()) == arity)
        .cloned()
        .collect::<Vec<_>>();
    if units.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    if let Some(return_type) = ctx.java().usage_facts_index().callable_return_type(&fqn) {
        return ReceiverAnalysisOutcome::Precise(vec![return_type.to_string()]);
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
    if let Some(return_type) = ctx
        .java()
        .usage_facts_index()
        .fact_for_declaration(method)
        .and_then(|facts| facts.return_type_fqn.as_deref())
    {
        return ReceiverAnalysisOutcome::Precise(vec![return_type.to_string()]);
    }

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
            .and_then(|type_node| ctx.resolve_type_fqn(type_node))
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
                .and_then(|type_node| java_type_fqn_from_node(ctx.java(), file, &source, type_node))
                .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
                .unwrap_or(ReceiverAnalysisOutcome::Unknown);
            (
                (unit.fq_name(), unit.signature().map(str::to_string)),
                outcome,
            )
        })
        .collect()
}

fn java_type_fqn_from_node(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<String> {
    let raw = node_text(type_node, source);
    let normalized = raw
        .split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim();
    (!normalized.is_empty())
        .then(|| java.resolve_type_name_in_file(file, normalized))
        .flatten()
        .map(|unit| unit.fq_name())
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
