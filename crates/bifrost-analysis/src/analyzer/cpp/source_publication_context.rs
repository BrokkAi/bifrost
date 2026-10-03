//! Normalized declaration-time guard and namespace context.
use crate::CancellationToken;
use crate::analyzer::store::source_facts::{check_cancelled, strict_bool};
use crate::analyzer::store::{Result, StoreError, usize_to_i64};
use brokk_bifrost_core::analyzer::cpp_facts::*;
use brokk_bifrost_core::hash::HashMap;
use rusqlite::{Transaction, params};

fn node_parts(node: &CppGuardNode) -> (i64, Option<&str>, Option<bool>, &[usize]) {
    match node {
        CppGuardNode::Defined(text) => (0, Some(text), None, &[]),
        CppGuardNode::Undefined(text) => (1, Some(text), None, &[]),
        CppGuardNode::Boolean(child) => (2, None, None, std::slice::from_ref(child)),
        CppGuardNode::Expression(text) => (3, Some(text), None, &[]),
        CppGuardNode::NegatedExpression(text) => (4, Some(text), None, &[]),
        CppGuardNode::Constant(value) => (5, None, Some(*value), &[]),
        CppGuardNode::Truthy(text) => (6, Some(text), None, &[]),
        CppGuardNode::Falsy(text) => (7, Some(text), None, &[]),
        CppGuardNode::Opaque(text) => (8, Some(text), None, &[]),
        CppGuardNode::NegatedOpaque(text) => (9, Some(text), None, &[]),
        CppGuardNode::All(children) => (10, None, None, children),
        CppGuardNode::Any(children) => (11, None, None, children),
    }
}

pub(crate) fn cost(facts: &CppSourceFacts) -> (usize, usize) {
    let mut rows = facts.declarations.len();
    let mut bytes = 0usize;
    for fact in &facts.declarations {
        if let Some(alias) = &fact.file_scope_alias {
            bytes = bytes
                .saturating_add(alias.name.len())
                .saturating_add(alias.target.len())
                .saturating_add(alias.namespace.as_ref().map_or(0, String::len));
        }
        if let Some(namespace) = &fact.flattened_macro_namespace {
            rows = rows.saturating_add(namespace.len());
            bytes = bytes.saturating_add(namespace.iter().map(String::len).sum::<usize>());
        }
        for set in [&fact.guard_requirements, &fact.callable_guards]
            .into_iter()
            .flatten()
        {
            rows = rows
                .saturating_add(1)
                .saturating_add(set.nodes.len())
                .saturating_add(set.roots.len());
            for node in &set.nodes {
                let (_, text, _, children) = node_parts(node);
                rows = rows.saturating_add(children.len());
                bytes = bytes.saturating_add(text.map_or(0, str::len));
            }
        }
    }
    (rows, bytes)
}

pub(crate) fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &CppSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut contexts = tx.prepare_cached("INSERT INTO source_cpp_declaration_contexts (blob_id,declaration_id,callable_activation,exhaustive_family,displaced_closing_brace,flattened_namespace_present,file_alias_name,file_alias_target,file_alias_namespace,callable_guard_completion_byte) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")?;
    let mut namespaces = tx.prepare_cached("INSERT INTO source_cpp_flattened_namespaces (blob_id,declaration_id,ordinal,component) VALUES(?1,?2,?3,?4)")?;
    let mut sets = tx.prepare_cached(
        "INSERT INTO source_cpp_guard_sets (blob_id,declaration_id,guard_kind) VALUES(?1,?2,?3)",
    )?;
    let mut nodes = tx.prepare_cached("INSERT INTO source_cpp_guard_nodes (blob_id,declaration_id,guard_kind,node_id,kind,text,constant) VALUES(?1,?2,?3,?4,?5,?6,?7)")?;
    let mut edges = tx.prepare_cached("INSERT INTO source_cpp_guard_edges (blob_id,declaration_id,guard_kind,parent_id,ordinal,child_id) VALUES(?1,?2,?3,?4,?5,?6)")?;
    let mut roots = tx.prepare_cached("INSERT INTO source_cpp_guard_roots (blob_id,declaration_id,guard_kind,ordinal,node_id) VALUES(?1,?2,?3,?4,?5)")?;
    for fact in &facts.declarations {
        check_cancelled(cancellation)?;
        let declaration = fact.declaration.get();
        contexts.execute(params![
            blob_id,
            declaration,
            fact.callable_activation.map(usize_to_i64).transpose()?,
            fact.exhaustive_conditional_family.map(|id| id.get()),
            fact.displaced_namespace_closing_brace.map(|id| id.get()),
            fact.flattened_macro_namespace.is_some(),
            fact.file_scope_alias
                .as_ref()
                .map(|alias| alias.name.as_str()),
            fact.file_scope_alias
                .as_ref()
                .map(|alias| alias.target.as_str()),
            fact.file_scope_alias
                .as_ref()
                .and_then(|alias| alias.namespace.as_deref()),
            fact.callable_guard_completion_byte
                .map(usize_to_i64)
                .transpose()?
        ])?;
        if let Some(namespace) = &fact.flattened_macro_namespace {
            for (ordinal, component) in namespace.iter().enumerate() {
                namespaces.execute(params![
                    blob_id,
                    declaration,
                    usize_to_i64(ordinal)?,
                    component
                ])?;
            }
        }
        for (guard_kind, set) in [&fact.guard_requirements, &fact.callable_guards]
            .into_iter()
            .enumerate()
        {
            let Some(set) = set else { continue };
            assert!(set.valid(), "invalid primary C++ guard arena");
            let guard_kind = usize_to_i64(guard_kind)?;
            sets.execute(params![blob_id, declaration, guard_kind])?;
            for (id, node) in set.nodes.iter().enumerate() {
                check_cancelled(cancellation)?;
                let (kind, text, constant, children) = node_parts(node);
                nodes.execute(params![
                    blob_id,
                    declaration,
                    guard_kind,
                    usize_to_i64(id)?,
                    kind,
                    text,
                    constant
                ])?;
                for (ordinal, child) in children.iter().enumerate() {
                    edges.execute(params![
                        blob_id,
                        declaration,
                        guard_kind,
                        usize_to_i64(id)?,
                        usize_to_i64(ordinal)?,
                        usize_to_i64(*child)?
                    ])?;
                }
            }
            for (ordinal, root) in set.roots.iter().enumerate() {
                roots.execute(params![
                    blob_id,
                    declaration,
                    guard_kind,
                    usize_to_i64(ordinal)?,
                    usize_to_i64(*root)?
                ])?;
            }
        }
    }
    Ok(())
}

pub(crate) fn read(
    tx: &Transaction<'_>,
    blob_id: i64,
    facts: &mut CppSourceFacts,
    keep_going: &dyn Fn() -> bool,
) -> Result<Option<()>> {
    macro_rules! rows {
        ($sql:expr, $row:ident, $body:block) => {{
            let mut statement = tx.prepare_cached($sql)?;
            let mut rows = statement.query([blob_id])?;
            while let Some($row) = rows.next()? {
                if !keep_going() {
                    return Ok(None);
                }
                $body
            }
        }};
    }
    let mut namespaces: HashMap<u32, Vec<String>> = HashMap::default();
    rows!(
        "SELECT declaration_id,ordinal,component FROM source_cpp_flattened_namespaces WHERE blob_id=?1 ORDER BY declaration_id,ordinal",
        row,
        {
            let values = namespaces.entry(row.get(0)?).or_default();
            dense(row.get(1)?, values.len())?;
            values.push(row.get(2)?);
        }
    );
    let mut edges: HashMap<(u32, i64, usize), Vec<usize>> = HashMap::default();
    rows!(
        "SELECT declaration_id,guard_kind,parent_id,ordinal,child_id FROM source_cpp_guard_edges WHERE blob_id=?1 ORDER BY declaration_id,guard_kind,parent_id,ordinal",
        row,
        {
            let key = (row.get(0)?, row.get(1)?, row.get(2)?);
            let children = edges.entry(key).or_default();
            dense(row.get(3)?, children.len())?;
            let child: usize = row.get(4)?;
            if child >= key.2 {
                return Err(StoreError::new("non-postorder C++ guard edge"));
            }
            children.push(child);
        }
    );
    let mut sets: HashMap<(u32, i64), CppGuardSet> = HashMap::default();
    rows!(
        "SELECT declaration_id,guard_kind FROM source_cpp_guard_sets WHERE blob_id=?1 ORDER BY declaration_id,guard_kind",
        row,
        {
            let key = (row.get(0)?, row.get(1)?);
            if !matches!(key.1, 0 | 1) {
                return Err(StoreError::new("invalid C++ guard set kind"));
            }
            sets.insert(key, CppGuardSet::new(Vec::new(), Vec::new()));
        }
    );
    rows!(
        "SELECT declaration_id,guard_kind,node_id,kind,text,constant FROM source_cpp_guard_nodes WHERE blob_id=?1 ORDER BY declaration_id,guard_kind,node_id",
        row,
        {
            let key = (row.get(0)?, row.get(1)?);
            let set = sets
                .get_mut(&key)
                .ok_or_else(|| StoreError::new("orphan C++ guard node"))?;
            let id: usize = row.get(2)?;
            dense(id, set.nodes.len())?;
            let kind: i64 = row.get(3)?;
            let text: Option<String> = row.get(4)?;
            let constant: Option<i64> = row.get(5)?;
            let mut children = edges.remove(&(key.0, key.1, id)).unwrap_or_default();
            if text.is_some() != matches!(kind, 0 | 1 | 3 | 4 | 6 | 7 | 8 | 9)
                || constant.is_some() != (kind == 5)
                || (!matches!(kind, 2 | 10 | 11) && !children.is_empty())
            {
                return Err(StoreError::new("invalid C++ guard node payload"));
            }
            let node = match kind {
                0 => CppGuardNode::Defined(text.unwrap()),
                1 => CppGuardNode::Undefined(text.unwrap()),
                2 => {
                    if children.len() != 1 {
                        return Err(StoreError::new("invalid C++ Boolean guard child"));
                    }
                    CppGuardNode::Boolean(children.pop().unwrap())
                }
                3 => CppGuardNode::Expression(text.unwrap()),
                4 => CppGuardNode::NegatedExpression(text.unwrap()),
                5 => CppGuardNode::Constant(strict_bool(constant.unwrap(), "C++ guard constant")?),
                6 => CppGuardNode::Truthy(text.unwrap()),
                7 => CppGuardNode::Falsy(text.unwrap()),
                8 => CppGuardNode::Opaque(text.unwrap()),
                9 => CppGuardNode::NegatedOpaque(text.unwrap()),
                10 => CppGuardNode::All(children),
                11 => CppGuardNode::Any(children),
                _ => return Err(StoreError::new("invalid C++ guard node kind")),
            };
            set.nodes.push(node);
        }
    );
    rows!(
        "SELECT declaration_id,guard_kind,ordinal,node_id FROM source_cpp_guard_roots WHERE blob_id=?1 ORDER BY declaration_id,guard_kind,ordinal",
        row,
        {
            let key = (row.get(0)?, row.get(1)?);
            let set = sets
                .get_mut(&key)
                .ok_or_else(|| StoreError::new("orphan C++ guard root"))?;
            dense(row.get(2)?, set.roots.len())?;
            set.roots.push(row.get(3)?);
        }
    );
    let indices: HashMap<_, _> = facts
        .declarations
        .iter()
        .enumerate()
        .map(|(index, fact)| (fact.declaration.get(), index))
        .collect();
    let mut context_count = 0usize;
    rows!(
        "SELECT declaration_id,callable_activation,exhaustive_family,displaced_closing_brace,flattened_namespace_present,file_alias_name,file_alias_target,file_alias_namespace,callable_guard_completion_byte FROM source_cpp_declaration_contexts WHERE blob_id=?1 ORDER BY declaration_id",
        row,
        {
            let declaration: u32 = row.get(0)?;
            let index = *indices
                .get(&declaration)
                .ok_or_else(|| StoreError::new("orphan C++ declaration context"))?;
            let fact = &mut facts.declarations[index];
            let alias_name: Option<String> = row.get(5)?;
            let alias_target: Option<String> = row.get(6)?;
            let alias_namespace: Option<String> = row.get(7)?;
            fact.file_scope_alias = match (alias_name, alias_target, alias_namespace) {
                (Some(name), Some(target), namespace) => Some(CppFileScopeAliasFact {
                    name,
                    target,
                    namespace,
                }),
                (None, None, None) => None,
                _ => return Err(StoreError::new("invalid C++ file-scope alias columns")),
            };
            fact.callable_activation = row.get(1)?;
            fact.callable_guard_completion_byte = row.get(8)?;
            fact.exhaustive_conditional_family = row
                .get::<_, Option<u32>>(2)?
                .map(brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new);
            fact.displaced_namespace_closing_brace = row
                .get::<_, Option<u32>>(3)?
                .map(brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new);
            if strict_bool(row.get(4)?, "C++ flattened namespace presence")? {
                fact.flattened_macro_namespace =
                    Some(namespaces.remove(&declaration).unwrap_or_default());
            }
            fact.guard_requirements = sets.remove(&(declaration, 0));
            fact.callable_guards = sets.remove(&(declaration, 1));
            context_count += 1;
        }
    );
    if context_count != facts.declarations.len()
        || !namespaces.is_empty()
        || !edges.is_empty()
        || !sets.is_empty()
    {
        return Err(StoreError::new(
            "incomplete or orphan C++ declaration context rows",
        ));
    }
    Ok(Some(()))
}

fn dense(actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(StoreError::new("non-dense C++ declaration context rows"));
    }
    Ok(())
}
