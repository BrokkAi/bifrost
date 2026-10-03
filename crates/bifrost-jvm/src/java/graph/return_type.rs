use super::JavaGraphSource;
use crate::java::graph_support::{
    JavaSource, UniqueClassInFile, resolve_java_usage_type_components_in,
};
use crate::java::source_facts::JavaFileSourceFacts;
use brokk_bifrost_core::analyzer::RelationalDefinitionFrontier;
use brokk_bifrost_core::analyzer::java_facts::{JavaSourceTypeId, JavaTypeSyntaxShape};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome,
};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Mutex;
use tree_sitter::Node;
#[cfg(test)]
use tree_sitter::Parser;

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
    fn relational_definitions(&self) -> &dyn RelationalDefinitionFrontier;
    fn call_answering_units(&self, owner: &str, name: &str, arity: usize) -> Vec<CodeUnit>;
    fn file(&self) -> &ProjectFile;
    fn source(&self) -> &str;
    fn root(&self) -> Node<'_>;
    fn method_return_cache(&self) -> &MethodReturnCache;
    fn method_anonymous_return_cache(&self) -> &MethodAnonymousReturnCache;
    fn file_return_cache(&self) -> &FileReturnCache;
}

pub fn method_return_type_for_owner_fqns<'a, C, I>(
    owners: I,
    token: QueryToken<'_>,
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
            .map(|owner| method_return_type_for_owner_fqn(owner, token, name, arity, ctx)),
    )
}

/// The method declarations `owner` writes that a call of `name` with `arity`
/// arguments can bind to.
///
/// One reading of "this type answers this call" serves both the return-type
/// question and the hierarchy walk that decides which type answers it, so a
/// level the walk skips can never be a level whose return type is then read.
pub fn java_call_answering_units<C>(
    owner: &str,
    _token: QueryToken<'_>,
    name: &str,
    arity: usize,
    ctx: &C,
) -> Vec<CodeUnit>
where
    C: JavaReturnTypeContext + ?Sized,
{
    ctx.call_answering_units(owner, name, arity)
}

pub fn method_return_type_for_owner_fqn<C>(
    owner: &str,
    token: QueryToken<'_>,
    name: &str,
    arity: usize,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let units = java_call_answering_units(owner, token, name, arity, ctx);
    if units.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    merge_receiver_type_outcomes(
        units
            .into_iter()
            .map(|unit| method_unit_declared_return_type(&unit, token, ctx)),
    )
}

fn method_unit_declared_return_type<C>(
    method: &CodeUnit,
    token: QueryToken<'_>,
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
    let outcome = method_unit_declared_return_type_uncached(method, token, ctx);
    ctx.method_return_cache()
        .lock()
        .expect("java return type cache poisoned")
        .insert(cache_key, outcome.clone());
    outcome
}

fn method_unit_declared_return_type_uncached<C>(
    method: &CodeUnit,
    token: QueryToken<'_>,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    if method.source() == ctx.file() {
        let Some(range) = ctx.java().ranges(method).first().copied() else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        return java_return_type_node_covering(ctx.root(), &range)
            .and_then(|type_node| {
                java_declared_type_fqn(
                    ctx.java(),
                    token,
                    ctx.relational_definitions(),
                    ctx.file(),
                    ctx.source(),
                    type_node,
                    method,
                )
            })
            .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown);
    }
    java_file_return_facts(ctx, token, method.source())
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
    token: QueryToken<'_>,
    name: &str,
    arity: usize,
    ctx: &C,
) -> Option<ReceiverAnalysisOutcome<String>>
where
    C: JavaReturnTypeContext + ?Sized,
{
    let units = java_call_answering_units(owner, token, name, arity, ctx);
    (!units.is_empty()).then(|| {
        merge_receiver_type_outcomes(
            units
                .iter()
                .map(|unit| method_unit_anonymous_return_type(unit, token, ctx)),
        )
    })
}

fn method_unit_anonymous_return_type<C>(
    method: &CodeUnit,
    token: QueryToken<'_>,
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
    let outcome = method_unit_anonymous_return_type_uncached(method, token, ctx);
    ctx.method_anonymous_return_cache()
        .lock()
        .expect("java anonymous return cache poisoned")
        .insert(cache_key, outcome.clone());
    outcome
}

fn method_unit_anonymous_return_type_uncached<C>(
    method: &CodeUnit,
    token: QueryToken<'_>,
    ctx: &C,
) -> ReceiverAnalysisOutcome<String>
where
    C: JavaReturnTypeContext + ?Sized,
{
    if method.source() == ctx.file() {
        let Some(range) = ctx.java().ranges(method).first().copied() else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        return method_declaration_covering(ctx.root(), &range)
            .map(|declaration| {
                method_declaration_anonymous_return_type(
                    ctx.java(),
                    token,
                    ctx.relational_definitions(),
                    ctx.file(),
                    ctx.source(),
                    declaration,
                    method,
                )
            })
            .unwrap_or(ReceiverAnalysisOutcome::Unknown);
    }
    java_file_return_facts(ctx, token, method.source())
        .anonymous_return_types
        .get(&FileReturnCacheKey {
            fq_name: method.fq_name(),
            signature: method.signature().map(str::to_string),
        })
        .cloned()
        .unwrap_or(ReceiverAnalysisOutcome::Unknown)
}

fn java_file_return_facts<C>(
    ctx: &C,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> JavaFileReturnFacts
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

    let index = build_java_file_return_facts(ctx, token, file);
    ctx.file_return_cache()
        .lock()
        .expect("java file return cache poisoned")
        .insert(file.clone(), index.clone());
    index
}

fn build_java_file_return_facts<C>(
    ctx: &C,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> JavaFileReturnFacts
where
    C: JavaReturnTypeContext + ?Sized,
{
    let Some(mounted) = ctx.java().declaration_source_facts(token, file) else {
        return JavaFileReturnFacts::default();
    };
    if !mounted.facts.valid_links(&mounted.source) {
        return JavaFileReturnFacts::default();
    }
    let mut declared_alternatives: HashMap<
        FileReturnCacheKey,
        Vec<ReceiverAnalysisOutcome<String>>,
    > = HashMap::default();
    let mut anonymous_alternatives: HashMap<
        FileReturnCacheKey,
        Vec<ReceiverAnalysisOutcome<String>>,
    > = HashMap::default();
    let mut callable_returns = HashMap::default();
    for fact in &mounted.facts.callable_returns {
        callable_returns
            .entry(fact.callable)
            .or_insert_with(Vec::new)
            .push(fact);
    }
    let mut anonymous_returns = HashMap::default();
    for fact in &mounted.facts.anonymous_returns {
        anonymous_returns
            .entry(fact.callable)
            .or_insert_with(Vec::new)
            .push(fact);
    }
    for (declaration, units) in &mounted.declaration_units {
        for unit in units.iter().filter(|unit| unit.is_function()) {
            let key = FileReturnCacheKey {
                fq_name: unit.fq_name(),
                signature: unit.signature().map(str::to_string),
            };
            let declared = callable_returns.get(declaration);
            if let Some(facts) = declared {
                for fact in facts {
                    let declared_type = fact
                        .ty
                        .and_then(|type_id| {
                            java_declared_source_type_fqn(
                                ctx.java(),
                                token,
                                ctx.relational_definitions(),
                                &mounted,
                                type_id,
                                unit,
                            )
                        })
                        .map(|fqn| ReceiverAnalysisOutcome::Precise(vec![fqn]))
                        .unwrap_or(ReceiverAnalysisOutcome::Unknown);
                    declared_alternatives
                        .entry(key.clone())
                        .or_default()
                        .push(declared_type);
                }
            } else {
                declared_alternatives
                    .entry(key.clone())
                    .or_default()
                    .push(ReceiverAnalysisOutcome::Unknown);
            }

            let anonymous = anonymous_returns.get(declaration);
            if let Some(facts) = anonymous {
                for fact in facts {
                    let anonymous_return_type = if fact.status
                        != brokk_bifrost_core::analyzer::java_facts::JavaAnonymousReturnStatus::AllAnonymous
                    {
                        ReceiverAnalysisOutcome::Unknown
                    } else {
                        let mut types = Vec::with_capacity(fact.returns.len());
                        for entry in &fact.returns {
                            let Some(fqn) = java_declared_source_type_fqn(
                                ctx.java(),
                                token,
                                ctx.relational_definitions(),
                                &mounted,
                                entry.declared_type,
                                unit,
                            ) else {
                                types.clear();
                                break;
                            };
                            types.push(fqn);
                        }
                        if types.is_empty() {
                            ReceiverAnalysisOutcome::Unknown
                        } else {
                            ReceiverAnalysisOutcome::Precise(types)
                        }
                    };
                    anonymous_alternatives
                        .entry(key.clone())
                        .or_default()
                        .push(anonymous_return_type);
                }
            } else {
                anonymous_alternatives
                    .entry(key)
                    .or_default()
                    .push(ReceiverAnalysisOutcome::Unknown);
            }
        }
    }

    let mut facts = JavaFileReturnFacts::default();
    for (key, alternatives) in declared_alternatives {
        facts.declared_types.insert(
            key,
            merge_same_declaration_receiver_type_outcomes(alternatives),
        );
    }
    for (key, alternatives) in anonymous_alternatives {
        facts.anonymous_return_types.insert(
            key,
            merge_same_declaration_receiver_type_outcomes(alternatives),
        );
    }
    facts
}

fn java_declared_source_type_fqn(
    java: &dyn JavaSource,
    token: QueryToken<'_>,
    definitions: &dyn RelationalDefinitionFrontier,
    mounted: &JavaFileSourceFacts,
    root: JavaSourceTypeId,
    declaration: &CodeUnit,
) -> Option<String> {
    let source_type_occurrence = mounted
        .facts
        .types
        .get(root.index())
        .map(|type_fact| type_fact.occurrence)?;
    let mut current = root;
    loop {
        current = match &mounted.facts.types.get(current.index())?.shape {
            JavaTypeSyntaxShape::Named { name, parameter } => {
                if parameter.is_some() {
                    return None;
                }
                let components = name.path();
                match java_local_type_from_source_facts(
                    java,
                    mounted,
                    source_type_occurrence,
                    declaration,
                    components,
                ) {
                    LexicalTypeResolution::Resolved(unit) => return Some(unit.fq_name()),
                    LexicalTypeResolution::Blocked => return None,
                    LexicalTypeResolution::NotFound => {}
                }
                return match java_lexical_type_from_declaration(
                    java,
                    token,
                    declaration,
                    components,
                ) {
                    LexicalTypeResolution::Resolved(unit) => Some(unit.fq_name()),
                    LexicalTypeResolution::NotFound => resolve_java_usage_type_components_in(
                        java,
                        token,
                        definitions,
                        declaration.source(),
                        name.path(),
                    )
                    .map(|unit| unit.fq_name()),
                    LexicalTypeResolution::Blocked => None,
                };
            }
            JavaTypeSyntaxShape::Generic { base, .. }
            | JavaTypeSyntaxShape::Array { element: base, .. }
            | JavaTypeSyntaxShape::Annotated(base) => *base,
            JavaTypeSyntaxShape::NonNominal | JavaTypeSyntaxShape::Unknown => return None,
        };
    }
}

fn java_declared_type_fqn(
    java: &dyn JavaSource,
    token: QueryToken<'_>,
    definitions: &dyn RelationalDefinitionFrontier,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    declaration: &CodeUnit,
) -> Option<String> {
    let components = java_type_name_components(type_node, source)?;
    match java_lexical_type_from_declaration(java, token, declaration, &components) {
        LexicalTypeResolution::Resolved(unit) => Some(unit.fq_name()),
        LexicalTypeResolution::Blocked => None,
        LexicalTypeResolution::NotFound => {
            resolve_java_usage_type_components_in(java, token, definitions, file, &components)
                .map(|unit| unit.fq_name())
        }
    }
}

pub fn java_type_name_from_node(type_node: Node<'_>, source: &str) -> Option<String> {
    java_type_name_components(type_node, source).map(|components| components.join("."))
}

pub fn java_type_name_components(type_node: Node<'_>, source: &str) -> Option<Vec<String>> {
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
    token: QueryToken<'_>,
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
    match java_local_type_from_node(java, file, node, &declaration, &components) {
        LexicalTypeResolution::NotFound => {}
        resolution => return resolution,
    }
    java_lexical_type_from_declaration(java, token, &declaration, &components)
}

fn java_local_type_from_node(
    java: &dyn JavaSource,
    file: &ProjectFile,
    node: Node<'_>,
    declaration: &CodeUnit,
    components: &[String],
) -> LexicalTypeResolution {
    let Some(first_component) = components.first() else {
        return LexicalTypeResolution::NotFound;
    };
    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }

    let mut scope = Some(declaration.clone());
    let mut visited = brokk_bifrost_core::hash::HashSet::default();
    while let Some(owner) = scope {
        if !visited.insert(owner.clone()) {
            return LexicalTypeResolution::Blocked;
        }
        scope = java.parent_of(&owner);
        if owner.is_module() {
            break;
        }
        if owner.is_class() {
            continue;
        }

        let candidates = java
            .direct_children_in_file(&owner)
            .into_iter()
            .filter(|candidate| {
                candidate.is_class()
                    && candidate.identifier() == first_component
                    && candidate.source() == file
                    && java_local_type_visible_at(java, candidate, root, node.start_byte())
            })
            .collect::<Vec<_>>();
        let mut candidates = candidates.into_iter();
        let Some(mut binding) = candidates.next() else {
            continue;
        };
        if candidates.next().is_some() {
            return LexicalTypeResolution::Blocked;
        }

        for component in &components[1..] {
            let nested = java
                .direct_children_in_file(&binding)
                .into_iter()
                .filter(|candidate| {
                    candidate.is_class()
                        && candidate.identifier() == component
                        && candidate.source() == file
                })
                .collect::<Vec<_>>();
            let mut nested = nested.into_iter();
            let Some(next) = nested.next() else {
                return LexicalTypeResolution::Blocked;
            };
            if nested.next().is_some() {
                return LexicalTypeResolution::Blocked;
            }
            binding = next;
        }
        return LexicalTypeResolution::Resolved(binding);
    }
    LexicalTypeResolution::NotFound
}

/// Resolve a foreign-file local class from canonical source facts. The source
/// rows retain both the class declaration and its nearest lexical scope, so a
/// foreign reader can apply the same declaration-before-use and scope rules as
/// the active-file AST path without reconstructing a parser tree.
fn java_local_type_from_source_facts(
    java: &dyn JavaSource,
    mounted: &JavaFileSourceFacts,
    type_occurrence: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
    declaration: &CodeUnit,
    components: &[String],
) -> LexicalTypeResolution {
    let Some(first_component) = components.first() else {
        return LexicalTypeResolution::NotFound;
    };
    let use_byte = mounted.source.occurrence(type_occurrence).range.start_byte;
    let mut candidates = Vec::new();
    for local in &mounted.facts.local_types {
        let declaration_row = mounted.source.declaration(local.declaration);
        let declaration_range = mounted.source.occurrence(declaration_row.occurrence).range;
        let scope_range = mounted.source.occurrence(local.lexical_scope).range;
        if declaration_range.start_byte >= use_byte
            || scope_range.start_byte > use_byte
            || use_byte >= scope_range.end_byte
        {
            continue;
        }
        let Some(units) = mounted.declaration_units.get(&local.declaration) else {
            // Source rows intentionally do not duplicate declaration-name
            // text. A visible local declaration with no bridge therefore
            // cannot be shown unrelated to this spelling; fail closed rather
            // than falling through to a package or import answer.
            return LexicalTypeResolution::Blocked;
        };
        for unit in units.iter().filter(|unit| {
            unit.is_class()
                && unit.identifier() == first_component
                && unit.source() == declaration.source()
        }) {
            let identity = (local.declaration, local.lexical_scope, unit.clone());
            if !candidates.iter().any(|existing| existing == &identity) {
                candidates.push(identity);
            }
        }
    }
    if candidates.is_empty() {
        return LexicalTypeResolution::NotFound;
    }

    let nearest_scope_width = candidates
        .iter()
        .map(|(_, scope, _)| {
            let range = mounted.source.occurrence(*scope).range;
            range.end_byte.saturating_sub(range.start_byte)
        })
        .min()
        .expect("non-empty local type candidates have a scope");
    candidates.retain(|(_, scope, _)| {
        let range = mounted.source.occurrence(*scope).range;
        range.end_byte.saturating_sub(range.start_byte) == nearest_scope_width
    });

    // Repeated bridge rows for one source declaration are harmless, but two
    // source declarations at the same nearest scope are an unresolved lexical
    // collision even when their rendered CodeUnit happens to compare equal.
    let identities = candidates
        .iter()
        .map(|(local, scope, _)| (*local, *scope))
        .collect::<brokk_bifrost_core::hash::HashSet<_>>();
    if identities.len() != 1 {
        return LexicalTypeResolution::Blocked;
    }
    let units = candidates
        .into_iter()
        .map(|(_, _, unit)| unit)
        .collect::<Vec<_>>();
    let mut units = units.into_iter();
    let Some(mut binding) = units.next() else {
        return LexicalTypeResolution::Blocked;
    };
    if units.next().is_some() {
        return LexicalTypeResolution::Blocked;
    }
    for component in &components[1..] {
        let nested = java
            .direct_children_in_file(&binding)
            .into_iter()
            .filter(|candidate| {
                candidate.is_class()
                    && candidate.identifier() == component
                    && candidate.source() == declaration.source()
            })
            .collect::<Vec<_>>();
        let mut nested = nested.into_iter();
        let Some(next) = nested.next() else {
            return LexicalTypeResolution::Blocked;
        };
        if nested.next().is_some() {
            return LexicalTypeResolution::Blocked;
        }
        binding = next;
    }
    LexicalTypeResolution::Resolved(binding)
}

fn java_local_type_visible_at(
    java: &dyn JavaSource,
    candidate: &CodeUnit,
    root: Node<'_>,
    byte: usize,
) -> bool {
    java.ranges(candidate).into_iter().any(|range| {
        if range.start_byte >= byte {
            return false;
        }
        let Some(declaration) = root.descendant_for_byte_range(range.start_byte, range.end_byte)
        else {
            return false;
        };
        java_local_type_scope_contains(declaration, byte)
    })
}

pub fn java_local_type_scope_contains(mut declaration: Node<'_>, byte: usize) -> bool {
    loop {
        if is_java_local_type_scope_node(declaration.kind()) {
            return declaration.start_byte() <= byte && byte < declaration.end_byte();
        }
        let Some(parent) = declaration.parent() else {
            return false;
        };
        declaration = parent;
    }
}

pub fn is_java_local_type_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "block"
            | "lambda_expression"
            | "catch_clause"
            | "enhanced_for_statement"
            | "for_statement"
            | "try_with_resources_statement"
    )
}

pub fn java_lexical_type_from_declaration(
    java: &dyn JavaSource,
    token: QueryToken<'_>,
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
        match unique_java_class_by_fqn_in_file(java, token, &nested_fqn, owner.source()) {
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
        return match unique_java_class_by_fqn_in_file(java, token, &qualified_fqn, owner.source()) {
            Ok(Some(unit)) => LexicalTypeResolution::Resolved(unit),
            Ok(None) | Err(()) => LexicalTypeResolution::Blocked,
        };
    }
    LexicalTypeResolution::NotFound
}

fn unique_java_class_by_fqn_in_file(
    java: &dyn JavaSource,
    _token: QueryToken<'_>,
    fqn: &str,
    file: &ProjectFile,
) -> Result<Option<CodeUnit>, ()> {
    match java.unique_class_by_fqn_in_file(fqn, file) {
        UniqueClassInFile::None => Ok(None),
        UniqueClassInFile::Unique(unit) => Ok(Some(unit)),
        UniqueClassInFile::Ambiguous => Err(()),
    }
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
    token: QueryToken<'_>,
    definitions: &dyn RelationalDefinitionFrontier,
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
            let Some(fqn) = java_declared_type_fqn(
                java,
                token,
                definitions,
                file,
                source,
                type_node,
                declaration,
            ) else {
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

/// Merge projections made from duplicate source declaration bridges for one
/// declaration identity. These alternatives are not overloads: a missing or
/// disagreeing bridge must poison precision rather than unioning an answer
/// that depends on map traversal order. The regular merge remains appropriate
/// for distinct overloads and hierarchy owners.
fn merge_same_declaration_receiver_type_outcomes(
    outcomes: impl IntoIterator<Item = ReceiverAnalysisOutcome<String>>,
) -> ReceiverAnalysisOutcome<String> {
    let mut outcomes = outcomes.into_iter();
    let Some(first) = outcomes.next() else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let ReceiverAnalysisOutcome::Precise(mut expected) = first else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    expected.sort();
    expected.dedup();
    if expected.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    for outcome in outcomes {
        let ReceiverAnalysisOutcome::Precise(mut actual) = outcome else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        actual.sort();
        actual.dedup();
        if actual != expected {
            return ReceiverAnalysisOutcome::Unknown;
        }
    }
    ReceiverAnalysisOutcome::Precise(expected)
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

    #[test]
    fn same_declaration_return_alternatives_require_set_agreement() {
        assert_eq!(
            merge_same_declaration_receiver_type_outcomes([
                ReceiverAnalysisOutcome::Precise(vec!["a.B".to_string(), "a.A".to_string()]),
                ReceiverAnalysisOutcome::Precise(vec!["a.A".to_string(), "a.B".to_string()]),
            ]),
            ReceiverAnalysisOutcome::Precise(vec!["a.A".to_string(), "a.B".to_string()]),
        );
        assert_eq!(
            merge_same_declaration_receiver_type_outcomes([
                ReceiverAnalysisOutcome::Precise(vec!["a.A".to_string()]),
                ReceiverAnalysisOutcome::Precise(vec!["a.B".to_string()]),
            ]),
            ReceiverAnalysisOutcome::Unknown,
        );
        assert_eq!(
            merge_same_declaration_receiver_type_outcomes([
                ReceiverAnalysisOutcome::Precise(vec!["a.A".to_string()]),
                ReceiverAnalysisOutcome::Unknown,
            ]),
            ReceiverAnalysisOutcome::Unknown,
        );
    }
}
