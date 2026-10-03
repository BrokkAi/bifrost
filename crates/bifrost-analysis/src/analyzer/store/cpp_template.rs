use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::{
    CppTemplateAliasTargetMetadata, CppTemplateExpression, CppTemplateMetadata,
    CppTemplateParameterKind, CppTemplateParameterMetadata, CppTemplateTerm,
};
use rusqlite::{Connection, Transaction, params};

use crate::CancellationToken;
use crate::analyzer::store::{
    Result, StoreError, UnitRow, chunk_params, chunk_placeholders, usize_to_i64,
};
use crate::hash::HashMap;

/// Expression roles as `unit_cpp_class_template_expressions.role` stores them.
const ROLE_PARAMETER_DEFAULT: i64 = 0;
const ROLE_SPECIALIZATION_ARGUMENT: i64 = 1;
const ROLE_ALIAS_ARGUMENT: i64 = 2;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PreparedCppTemplates {
    headers: Vec<HeaderRow>,
    parameters: Vec<ParameterRow>,
    alias_components: Vec<AliasComponentRow>,
    expressions: Vec<ExpressionRow>,
    terms: Vec<TemplateTermRow>,
}

#[derive(Debug, PartialEq, Eq)]
struct HeaderRow {
    unit_key: i64,
    primary_name: String,
    primary_fq_name: String,
    alias_global: Option<bool>,
    alias_arguments_present: Option<bool>,
    parameter_count: usize,
    specialization_argument_count: usize,
    alias_component_count: usize,
    alias_argument_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ParameterRow {
    unit_key: i64,
    ordinal: usize,
    name: String,
    kind: i64,
    variadic: bool,
    default_present: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct AliasComponentRow {
    unit_key: i64,
    ordinal: usize,
    component: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ExpressionRow {
    id: i64,
    unit_key: i64,
    role: i64,
    owner_ordinal: usize,
    text: String,
    root_term: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TemplateTermRow {
    pub(crate) id: i64,
    pub(crate) expression: i64,
    pub(crate) parent: Option<i64>,
    pub(crate) ordinal: usize,
    pub(crate) kind: i64,
    pub(crate) text: Option<String>,
    pub(crate) atom_kind: Option<String>,
}

pub(crate) fn flatten_template_expression(
    expression_id: i64,
    first_term_id: i64,
    expression: &CppTemplateExpression,
) -> Result<(i64, Vec<TemplateTermRow>)> {
    let mut rows = Vec::new();
    let mut stack = vec![(&expression.term, None, 0usize)];
    while let Some((term, parent, ordinal)) = stack.pop() {
        let id =
            first_term_id
                .checked_add(i64::try_from(rows.len()).map_err(|_| {
                    StoreError::new("C++ template term count exceeds SQLite INTEGER")
                })?)
                .ok_or_else(|| StoreError::new("C++ template term id overflow"))?;
        let (kind, text, atom_kind, children) = match term {
            CppTemplateTerm::Parameter(name) => (0, Some(name.clone()), None, None),
            CppTemplateTerm::Atom { kind, text } => {
                (1, Some(text.clone()), Some(kind.clone()), None)
            }
            CppTemplateTerm::Node { kind, children } => {
                (2, None, Some(kind.clone()), Some(children.as_slice()))
            }
        };
        rows.push(TemplateTermRow {
            id,
            expression: expression_id,
            parent,
            ordinal,
            kind,
            text,
            atom_kind,
        });
        if let Some(children) = children {
            for (ordinal, child) in children.iter().enumerate().rev() {
                stack.push((child, Some(id), ordinal));
            }
        }
    }
    Ok((first_term_id, rows))
}

pub(crate) fn build_template_term(
    rows: Vec<TemplateTermRow>,
    root_term: i64,
) -> Result<CppTemplateTerm> {
    let expression = rows
        .first()
        .ok_or_else(|| StoreError::new("C++ template expression has no terms"))?
        .expression;
    let mut by_id: HashMap<i64, usize> = HashMap::default();
    let mut children: HashMap<i64, Vec<(usize, i64)>> = HashMap::default();
    let mut roots = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row.expression != expression {
            return Err(StoreError::new(
                "C++ template term belongs to a different expression",
            ));
        }
        if by_id.insert(row.id, index).is_some() {
            return Err(StoreError::new("duplicate C++ template term id"));
        }
        if let Some(parent) = row.parent {
            if parent >= row.id || !by_id.contains_key(&parent) {
                return Err(StoreError::new("C++ template term parent is not earlier"));
            }
            children
                .entry(parent)
                .or_default()
                .push((row.ordinal, row.id));
        } else {
            roots.push(row.id);
        }
    }
    if roots.len() != 1 || roots[0] != root_term {
        return Err(StoreError::new(
            "C++ template expression must have one root term",
        ));
    }
    let root_index = *by_id
        .get(&root_term)
        .ok_or_else(|| StoreError::new("missing C++ template root"))?;
    if rows[root_index].ordinal != 0 {
        return Err(StoreError::new(
            "C++ template expression root ordinal must be zero",
        ));
    }
    for values in children.values_mut() {
        values.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        for (ordinal, (actual, _)) in values.iter().enumerate() {
            if *actual != ordinal {
                return Err(StoreError::new("non-dense C++ template child ordinals"));
            }
        }
    }
    let mut built: Vec<Option<CppTemplateTerm>> = (0..rows.len()).map(|_| None).collect();
    for index in (0..rows.len()).rev() {
        let row = &rows[index];
        let child_ids = children.remove(&row.id).unwrap_or_default();
        let mut row_children = Vec::with_capacity(child_ids.len());
        for (_, child_id) in child_ids {
            let child_index = *by_id
                .get(&child_id)
                .ok_or_else(|| StoreError::new("missing C++ template child"))?;
            row_children.push(
                built[child_index]
                    .take()
                    .ok_or_else(|| StoreError::new("C++ template child is not built"))?,
            );
        }
        let term = match row.kind {
            0 => {
                if row.text.is_none() || row.atom_kind.is_some() || !row_children.is_empty() {
                    return Err(StoreError::new("invalid C++ template parameter row"));
                }
                CppTemplateTerm::Parameter(row.text.clone().expect("checked above"))
            }
            1 => {
                if row.text.is_none() || row.atom_kind.is_none() || !row_children.is_empty() {
                    return Err(StoreError::new("invalid C++ template atom row"));
                }
                CppTemplateTerm::Atom {
                    kind: row.atom_kind.clone().expect("checked above"),
                    text: row.text.clone().expect("checked above"),
                }
            }
            2 => {
                if row.text.is_some() || row.atom_kind.is_none() {
                    return Err(StoreError::new("invalid C++ template node row"));
                }
                CppTemplateTerm::Node {
                    kind: row.atom_kind.clone().expect("checked above"),
                    children: row_children,
                }
            }
            value => {
                return Err(StoreError::new(format!(
                    "invalid C++ template term kind {value}"
                )));
            }
        };
        built[index] = Some(term);
    }
    if !children.is_empty() {
        return Err(StoreError::new("orphan C++ template child rows"));
    }
    built[root_index]
        .take()
        .ok_or_else(|| StoreError::new("C++ template root is not built"))
}

impl PreparedCppTemplates {
    pub(super) fn prepare(
        metadata: &HashMap<CodeUnit, CppTemplateMetadata>,
        unit_keys: &HashMap<CodeUnit, i64>,
    ) -> Result<Self> {
        let mut keyed = metadata
            .iter()
            .map(|(unit, value)| {
                (
                    *unit_keys.get(unit).unwrap_or_else(|| {
                        panic!("C++ class-template metadata owner is not persisted: {unit:?}")
                    }),
                    value,
                )
            })
            .collect::<Vec<_>>();
        keyed.sort_unstable_by_key(|(key, _)| *key);

        let mut prepared = Self::default();
        for (unit_key, metadata) in keyed {
            for (ordinal, parameter) in metadata.parameters.iter().enumerate() {
                prepared.parameters.push(ParameterRow {
                    unit_key,
                    ordinal,
                    name: parameter.name.clone(),
                    kind: match parameter.kind {
                        CppTemplateParameterKind::Type => 0,
                        CppTemplateParameterKind::Value => 1,
                        CppTemplateParameterKind::Template => 2,
                    },
                    variadic: parameter.variadic,
                    default_present: parameter.default.is_some(),
                });
                if let Some(expression) = &parameter.default {
                    prepared.push_expression(
                        unit_key,
                        ROLE_PARAMETER_DEFAULT,
                        ordinal,
                        expression,
                    )?;
                }
            }
            for (ordinal, expression) in metadata.specialization_arguments.iter().enumerate() {
                prepared.push_expression(
                    unit_key,
                    ROLE_SPECIALIZATION_ARGUMENT,
                    ordinal,
                    expression,
                )?;
            }
            if let Some(alias) = &metadata.alias_target {
                for (ordinal, component) in alias.components.iter().enumerate() {
                    prepared.alias_components.push(AliasComponentRow {
                        unit_key,
                        ordinal,
                        component: component.clone(),
                    });
                }
                if let Some(arguments) = &alias.arguments {
                    for (ordinal, expression) in arguments.iter().enumerate() {
                        prepared.push_expression(
                            unit_key,
                            ROLE_ALIAS_ARGUMENT,
                            ordinal,
                            expression,
                        )?;
                    }
                }
            }
            prepared.headers.push(HeaderRow {
                unit_key,
                primary_name: metadata.primary_name.clone(),
                primary_fq_name: metadata.primary_fq_name.clone(),
                alias_global: metadata.alias_target.as_ref().map(|alias| alias.global),
                alias_arguments_present: metadata
                    .alias_target
                    .as_ref()
                    .map(|alias| alias.arguments.is_some()),
                parameter_count: metadata.parameters.len(),
                specialization_argument_count: metadata.specialization_arguments.len(),
                alias_component_count: metadata
                    .alias_target
                    .as_ref()
                    .map_or(0, |alias| alias.components.len()),
                alias_argument_count: metadata
                    .alias_target
                    .as_ref()
                    .and_then(|alias| alias.arguments.as_ref())
                    .map_or(0, Vec::len),
            });
        }
        Ok(prepared)
    }

    fn push_expression(
        &mut self,
        unit_key: i64,
        role: i64,
        owner_ordinal: usize,
        expression: &CppTemplateExpression,
    ) -> Result<()> {
        let id = usize_to_i64(self.expressions.len())?;
        let first_term = usize_to_i64(self.terms.len())?;
        let (root_term, terms) = flatten_template_expression(id, first_term, expression)?;
        self.terms.extend(terms);
        self.expressions.push(ExpressionRow {
            id,
            unit_key,
            role,
            owner_ordinal,
            text: expression.text.clone(),
            root_term,
        });
        Ok(())
    }

    pub(super) fn header_count(&self) -> usize {
        self.headers.len()
    }

    pub(super) fn logical_rows(&self) -> usize {
        self.headers
            .len()
            .saturating_add(self.parameters.len())
            .saturating_add(self.alias_components.len())
            .saturating_add(self.expressions.len())
            .saturating_add(self.terms.len())
    }

    pub(super) fn payload_bytes(&self) -> usize {
        self.headers
            .iter()
            .map(|row| {
                row.primary_name
                    .len()
                    .saturating_add(row.primary_fq_name.len())
            })
            .chain(self.parameters.iter().map(|row| row.name.len()))
            .chain(self.alias_components.iter().map(|row| row.component.len()))
            .chain(self.expressions.iter().map(|row| row.text.len()))
            .chain(
                self.terms
                    .iter()
                    .map(|row| row.text.as_ref().map_or(0, String::len))
                    .chain(
                        self.terms
                            .iter()
                            .map(|row| row.atom_kind.as_ref().map_or(0, String::len)),
                    ),
            )
            .fold(0usize, usize::saturating_add)
    }

    pub(super) fn insert(
        &self,
        tx: &Transaction<'_>,
        blob_id: i64,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut parameters = tx.prepare_cached(
            "INSERT INTO unit_cpp_class_template_parameters
             (blob_id, unit_key, ordinal, name, kind, variadic, default_present)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &self.parameters {
            if cancellation.is_cancelled() {
                return Err(StoreError::new("C++ template publication cancelled"));
            }
            parameters.execute(params![
                blob_id,
                row.unit_key,
                usize_to_i64(row.ordinal)?,
                row.name,
                row.kind,
                row.variadic,
                row.default_present,
            ])?;
        }
        drop(parameters);

        let mut components = tx.prepare_cached(
            "INSERT INTO unit_cpp_class_template_alias_components
             (blob_id, unit_key, ordinal, component) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for row in &self.alias_components {
            components.execute(params![
                blob_id,
                row.unit_key,
                usize_to_i64(row.ordinal)?,
                row.component,
            ])?;
        }
        drop(components);

        let mut expressions = tx.prepare_cached(
            "INSERT INTO unit_cpp_class_template_expressions
             (blob_id, expression_id, unit_key, role, owner_ordinal, text, root_term_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in &self.expressions {
            expressions.execute(params![
                blob_id,
                row.id,
                row.unit_key,
                row.role,
                usize_to_i64(row.owner_ordinal)?,
                row.text,
                row.root_term,
            ])?;
        }
        drop(expressions);

        let mut terms = tx.prepare_cached(
            "INSERT INTO unit_cpp_class_template_terms
             (blob_id, term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in &self.terms {
            terms.execute(params![
                blob_id,
                row.id,
                row.expression,
                row.parent,
                usize_to_i64(row.ordinal)?,
                row.kind,
                row.text,
                row.atom_kind,
            ])?;
        }
        drop(terms);

        let mut headers = tx.prepare_cached(
            "INSERT INTO unit_cpp_class_templates
             (blob_id, unit_key, primary_name, primary_fq_name, alias_global,
              alias_arguments_present, parameter_count, specialization_argument_count,
              alias_component_count, alias_argument_count)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;
        for row in &self.headers {
            headers.execute(params![
                blob_id,
                row.unit_key,
                row.primary_name,
                row.primary_fq_name,
                row.alias_global,
                row.alias_arguments_present,
                usize_to_i64(row.parameter_count)?,
                usize_to_i64(row.specialization_argument_count)?,
                usize_to_i64(row.alias_component_count)?,
                usize_to_i64(row.alias_argument_count)?,
            ])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RawHeader {
    unit_key: i64,
    primary_name: String,
    primary_fq_name: String,
    alias_global: Option<bool>,
    alias_arguments_present: Option<bool>,
    parameter_count: usize,
    specialization_argument_count: usize,
    alias_component_count: usize,
    alias_argument_count: usize,
}

#[derive(Debug)]
struct RawParameter {
    ordinal: usize,
    name: String,
    kind: i64,
    variadic: bool,
    default_present: bool,
}

#[derive(Default)]
struct RawBlob {
    headers: Vec<RawHeader>,
    parameters: HashMap<i64, Vec<RawParameter>>,
    alias_components: HashMap<i64, Vec<String>>,
    expressions: HashMap<i64, (i64, i64, usize, String, i64)>,
    terms: HashMap<i64, Vec<TemplateTermRow>>,
}

pub(super) fn read_bulk(
    conn: &Connection,
    lang: &str,
    oids: &[String],
) -> Result<HashMap<String, HashMap<i64, CppTemplateMetadata>>> {
    let mut blobs: HashMap<String, RawBlob> = HashMap::default();
    for chunk in oids.chunks(900) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders = chunk_placeholders(chunk);
        let query = |table: &str, columns: &str, order: &str| {
            format!(
                "SELECT keys.blob_oid, {columns} FROM blobs AS keys
                 JOIN {table} AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, {order}"
            )
        };
        let parameters = chunk_params(lang, chunk);

        let mut statement = conn.prepare_cached(&query(
            "unit_cpp_class_templates",
            "facts.unit_key, facts.primary_name, facts.primary_fq_name, facts.alias_global,
             facts.alias_arguments_present, facts.parameter_count,
             facts.specialization_argument_count, facts.alias_component_count,
             facts.alias_argument_count",
            "facts.unit_key",
        ))?;
        let mut rows = statement.query(rusqlite::params_from_iter(parameters.iter()))?;
        while let Some(row) = rows.next()? {
            blobs
                .entry(row.get(0)?)
                .or_default()
                .headers
                .push(RawHeader {
                    unit_key: row.get(1)?,
                    primary_name: row.get(2)?,
                    primary_fq_name: row.get(3)?,
                    alias_global: row.get(4)?,
                    alias_arguments_present: row.get(5)?,
                    parameter_count: row.get(6)?,
                    specialization_argument_count: row.get(7)?,
                    alias_component_count: row.get(8)?,
                    alias_argument_count: row.get(9)?,
                });
        }
        drop(rows);
        drop(statement);

        let mut statement = conn.prepare_cached(&query(
            "unit_cpp_class_template_parameters",
            "facts.unit_key, facts.ordinal, facts.name, facts.kind, facts.variadic,
             facts.default_present",
            "facts.unit_key, facts.ordinal",
        ))?;
        let mut rows = statement.query(rusqlite::params_from_iter(parameters.iter()))?;
        while let Some(row) = rows.next()? {
            blobs
                .entry(row.get(0)?)
                .or_default()
                .parameters
                .entry(row.get(1)?)
                .or_default()
                .push(RawParameter {
                    ordinal: row.get(2)?,
                    name: row.get(3)?,
                    kind: row.get(4)?,
                    variadic: row.get(5)?,
                    default_present: row.get(6)?,
                });
        }
        drop(rows);
        drop(statement);

        let mut statement = conn.prepare_cached(&query(
            "unit_cpp_class_template_alias_components",
            "facts.unit_key, facts.component",
            "facts.unit_key, facts.ordinal",
        ))?;
        let mut rows = statement.query(rusqlite::params_from_iter(parameters.iter()))?;
        while let Some(row) = rows.next()? {
            blobs
                .entry(row.get(0)?)
                .or_default()
                .alias_components
                .entry(row.get(1)?)
                .or_default()
                .push(row.get(2)?);
        }
        drop(rows);
        drop(statement);

        let mut statement = conn.prepare_cached(&query(
            "unit_cpp_class_template_expressions",
            "facts.expression_id, facts.unit_key, facts.role, facts.owner_ordinal,
             facts.text, facts.root_term_id",
            "facts.expression_id",
        ))?;
        let mut rows = statement.query(rusqlite::params_from_iter(parameters.iter()))?;
        while let Some(row) = rows.next()? {
            let oid: String = row.get(0)?;
            let id = row.get(1)?;
            if blobs
                .entry(oid)
                .or_default()
                .expressions
                .insert(
                    id,
                    (
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ),
                )
                .is_some()
            {
                return Err(StoreError::new(
                    "duplicate C++ class-template expression id",
                ));
            }
        }
        drop(rows);
        drop(statement);

        let mut statement = conn.prepare_cached(&query(
            "unit_cpp_class_template_terms",
            "facts.term_id, facts.expression_id, facts.parent_term_id, facts.ordinal,
             facts.kind, facts.text, facts.atom_kind",
            "facts.term_id",
        ))?;
        let mut rows = statement.query(rusqlite::params_from_iter(parameters.iter()))?;
        while let Some(row) = rows.next()? {
            let oid: String = row.get(0)?;
            let expression = row.get(2)?;
            blobs
                .entry(oid)
                .or_default()
                .terms
                .entry(expression)
                .or_default()
                .push(TemplateTermRow {
                    id: row.get(1)?,
                    expression,
                    parent: row.get(3)?,
                    ordinal: row.get(4)?,
                    kind: row.get(5)?,
                    text: row.get(6)?,
                    atom_kind: row.get(7)?,
                });
        }
    }

    blobs
        .into_iter()
        .map(|(oid, raw)| Ok((oid, hydrate_blob(raw)?)))
        .collect()
}

fn hydrate_blob(mut raw: RawBlob) -> Result<HashMap<i64, CppTemplateMetadata>> {
    let mut expressions: HashMap<(i64, i64), Vec<(usize, CppTemplateExpression)>> =
        HashMap::default();
    for (expression_id, (unit_key, role, owner, text, root)) in raw.expressions {
        let term_rows = raw
            .terms
            .remove(&expression_id)
            .ok_or_else(|| StoreError::new("C++ class-template expression has no terms"))?;
        expressions.entry((unit_key, role)).or_default().push((
            owner,
            CppTemplateExpression {
                text,
                term: build_template_term(term_rows, root)?,
            },
        ));
    }
    if !raw.terms.is_empty() {
        return Err(StoreError::new("orphan C++ class-template terms"));
    }
    for ((_, role), values) in &mut expressions {
        values.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        if *role == ROLE_PARAMETER_DEFAULT {
            // A default's owner ordinal is its parameter's ordinal, and only
            // some parameters carry a default, so this set is sparse by
            // construction. Strict increase is the whole invariant here; the
            // parameter walk below pairs each default with the parameter that
            // declared `default_present`.
            if values.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
                return Err(StoreError::new(
                    "repeated C++ class-template parameter default ordinals",
                ));
            }
        } else if values
            .iter()
            .enumerate()
            .any(|(expected, (actual, _))| expected != *actual)
        {
            return Err(StoreError::new(
                "non-dense C++ class-template expression ordinals",
            ));
        }
    }

    let mut result = HashMap::default();
    for header in raw.headers {
        let parameters = raw.parameters.remove(&header.unit_key).unwrap_or_default();
        if parameters.len() != header.parameter_count
            || parameters
                .iter()
                .enumerate()
                .any(|(expected, row)| expected != row.ordinal)
        {
            return Err(StoreError::new(
                "invalid C++ class-template parameter count",
            ));
        }
        let mut defaults = expressions
            .remove(&(header.unit_key, ROLE_PARAMETER_DEFAULT))
            .unwrap_or_default()
            .into_iter()
            .peekable();
        let parameters = parameters
            .into_iter()
            .map(|row| {
                let default = if defaults
                    .peek()
                    .is_some_and(|(ordinal, _)| *ordinal == row.ordinal)
                {
                    Some(defaults.next().expect("peeked default exists").1)
                } else {
                    None
                };
                if row.default_present != default.is_some() {
                    return Err(StoreError::new(
                        "invalid C++ class-template parameter default",
                    ));
                }
                let kind = match row.kind {
                    0 => CppTemplateParameterKind::Type,
                    1 => CppTemplateParameterKind::Value,
                    2 => CppTemplateParameterKind::Template,
                    value => {
                        return Err(StoreError::new(format!(
                            "invalid C++ class-template parameter kind {value}"
                        )));
                    }
                };
                Ok(CppTemplateParameterMetadata {
                    name: row.name,
                    kind,
                    variadic: row.variadic,
                    default,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if defaults.next().is_some() {
            return Err(StoreError::new(
                "orphan C++ class-template parameter defaults",
            ));
        }
        let specialization_arguments = expressions
            .remove(&(header.unit_key, ROLE_SPECIALIZATION_ARGUMENT))
            .unwrap_or_default()
            .into_iter()
            .map(|(_, expression)| expression)
            .collect::<Vec<_>>();
        if specialization_arguments.len() != header.specialization_argument_count {
            return Err(StoreError::new("invalid C++ specialization argument count"));
        }
        let alias_components = raw
            .alias_components
            .remove(&header.unit_key)
            .unwrap_or_default();
        if alias_components.len() != header.alias_component_count {
            return Err(StoreError::new(
                "invalid C++ template alias component count",
            ));
        }
        let alias_arguments = expressions
            .remove(&(header.unit_key, ROLE_ALIAS_ARGUMENT))
            .unwrap_or_default()
            .into_iter()
            .map(|(_, expression)| expression)
            .collect::<Vec<_>>();
        if alias_arguments.len() != header.alias_argument_count {
            return Err(StoreError::new("invalid C++ template alias argument count"));
        }
        let alias_target = match (header.alias_global, header.alias_arguments_present) {
            (None, None) if alias_components.is_empty() && alias_arguments.is_empty() => None,
            (None, None) => {
                return Err(StoreError::new(
                    "absent C++ template alias has relational children",
                ));
            }
            (Some(global), Some(true)) => Some(CppTemplateAliasTargetMetadata {
                components: alias_components,
                global,
                arguments: Some(alias_arguments),
            }),
            (Some(global), Some(false)) if alias_arguments.is_empty() => {
                Some(CppTemplateAliasTargetMetadata {
                    components: alias_components,
                    global,
                    arguments: None,
                })
            }
            (Some(_), Some(false)) => {
                return Err(StoreError::new(
                    "C++ template alias without arguments has argument rows",
                ));
            }
            _ => return Err(StoreError::new("inconsistent C++ template alias presence")),
        };
        if result
            .insert(
                header.unit_key,
                CppTemplateMetadata {
                    primary_name: header.primary_name,
                    primary_fq_name: header.primary_fq_name,
                    parameters,
                    specialization_arguments,
                    alias_target,
                },
            )
            .is_some()
        {
            return Err(StoreError::new("duplicate C++ class-template unit"));
        }
    }
    if !raw.parameters.is_empty() || !raw.alias_components.is_empty() || !expressions.is_empty() {
        return Err(StoreError::new("orphan C++ class-template rows"));
    }
    Ok(result)
}

pub(super) fn map_for_file(
    rows: Option<&HashMap<i64, CppTemplateMetadata>>,
    by_key: &HashMap<i64, UnitRow>,
) -> Result<HashMap<CodeUnit, CppTemplateMetadata>> {
    rows.into_iter()
        .flatten()
        .map(|(key, metadata)| {
            let unit = by_key
                .get(key)
                .ok_or_else(|| StoreError::new("C++ class-template metadata names missing unit"))?
                .unit
                .clone();
            Ok((unit, metadata.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::model::CppTemplateTerm;

    fn parameter_row(expression: i64, ordinal: usize) -> TemplateTermRow {
        TemplateTermRow {
            id: 0,
            expression,
            parent: None,
            ordinal,
            kind: 0,
            text: Some("T".into()),
            atom_kind: None,
        }
    }

    #[test]
    fn hydration_rejects_cross_expression_rows() {
        let mut rows = vec![parameter_row(1, 0)];
        rows.push(TemplateTermRow {
            id: 1,
            expression: 2,
            parent: Some(0),
            ordinal: 0,
            kind: 0,
            text: Some("U".into()),
            atom_kind: None,
        });
        assert!(build_template_term(rows, 0).is_err());
    }

    #[test]
    fn hydration_rejects_nonzero_root_ordinal() {
        assert!(build_template_term(vec![parameter_row(1, 1)], 0).is_err());
    }

    #[test]
    fn hydration_rejects_child_attached_to_leaf() {
        let mut rows = vec![parameter_row(1, 0)];
        rows.push(TemplateTermRow {
            id: 1,
            expression: 1,
            parent: Some(0),
            ordinal: 0,
            kind: 0,
            text: Some("U".into()),
            atom_kind: None,
        });
        assert!(build_template_term(rows, 0).is_err());
    }

    #[test]
    fn expression_round_trip_is_iterative_and_lossless() {
        let expression = CppTemplateExpression {
            text: "Wrap<T, 4>".into(),
            term: CppTemplateTerm::Node {
                kind: "template_type".into(),
                children: vec![
                    CppTemplateTerm::Parameter("T".into()),
                    CppTemplateTerm::Atom {
                        kind: "number_literal".into(),
                        text: "4".into(),
                    },
                ],
            },
        };
        let (root, rows) = flatten_template_expression(7, 11, &expression).unwrap();
        assert_eq!(build_template_term(rows, root).unwrap(), expression.term);
    }
}
