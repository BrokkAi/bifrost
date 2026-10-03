//! Relational publication of JavaScript and TypeScript declaration facts.

use brokk_bifrost_core::analyzer::js_ts_facts::{
    JsTsExportKind, JsTsReceiverBinding, JsTsSourceFacts, JsTsSourceTypeId, JsTsTypeShape,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::SourceImportId;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use rusqlite::{Transaction, params};

use crate::CancellationToken;
use crate::analyzer::store::source_facts::check_cancelled;
use crate::analyzer::store::{Result, SourceFactStorage, usize_to_i64};

pub(crate) static SOURCE_STORAGE: SourceFactStorage = SourceFactStorage {
    cost: |source| source.js_ts.as_ref().map(cost),
    insert,
};

pub(crate) fn cost(facts: &JsTsSourceFacts) -> (usize, usize) {
    let (
        _,
        _,
        _,
        type_names,
        type_children,
        type_members,
        type_parameters,
        declaration_parameters,
        component_members,
        declaration_bindings,
        property_receivers,
        property_receiver_members,
    ) = relational_counts(facts);
    let rows = 1
        + facts.bindings.len()
        + facts.exports.len()
        + facts.declarations.len()
        + facts.types.len()
        + type_names
        + type_children
        + type_members
        + type_parameters
        + declaration_parameters
        + component_members
        + declaration_bindings
        + property_receivers
        + property_receiver_members;
    let payload = facts
        .exports
        .iter()
        .map(|fact| {
            fact.name.as_ref().map_or(0, String::len)
                + match &fact.kind {
                    JsTsExportKind::Local { local_name } => local_name.len(),
                    JsTsExportKind::Default { local_name } => {
                        local_name.as_ref().map_or(0, String::len)
                    }
                    JsTsExportKind::ReexportNamed { .. }
                    | JsTsExportKind::ReexportModule { .. }
                    | JsTsExportKind::Star { .. } => 0,
                }
        })
        .chain(facts.declarations.iter().flat_map(|fact| {
            fact.component_props.as_ref().into_iter().flat_map(|props| match props {
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Named(name) => {
                    std::iter::once(name.len()).collect::<Vec<_>>()
                }
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::TypeMember { members, .. } => {
                    members.iter().map(String::len).collect::<Vec<_>>()
                }
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Type(_)
                | brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Module(_) => {
                    Vec::new()
                }
            })
        }))
        .chain(facts.declaration_bindings.iter().map(|binding| binding.name.len()))
        .chain(facts.property_receivers.iter().flat_map(|receiver| {
            std::iter::once(receiver.receiver_root.len())
                .chain(receiver.members.iter().map(String::len))
                .collect::<Vec<_>>()
        }))
        .chain(facts.types.iter().map(|fact| match &fact.shape {
            JsTsTypeShape::Named(names) => names.iter().map(String::len).sum(),
            JsTsTypeShape::Object(members) => {
                members.iter().map(|(name, _)| name.len()).sum()
            }
            _ => 0,
        }))
        .fold(0usize, usize::saturating_add);
    (rows, payload)
}

fn relational_counts(
    facts: &JsTsSourceFacts,
) -> (
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) {
    let mut type_names = 0;
    let mut type_children = 0;
    let mut type_members = 0;
    let mut type_parameters = 0;
    for fact in &facts.types {
        match &fact.shape {
            JsTsTypeShape::Named(names) => type_names += names.len(),
            JsTsTypeShape::Generic { arguments, .. }
            | JsTsTypeShape::Union(arguments)
            | JsTsTypeShape::Intersection(arguments)
            | JsTsTypeShape::Tuple(arguments) => type_children += arguments.len(),
            JsTsTypeShape::Function { parameters, .. } => type_parameters += parameters.len(),
            JsTsTypeShape::Object(members) => type_members += members.len(),
            JsTsTypeShape::Wrapped(_)
            | JsTsTypeShape::Query(_)
            | JsTsTypeShape::Array(_)
            | JsTsTypeShape::NoReceiver
            | JsTsTypeShape::Unknown => {}
        }
    }
    let declaration_parameters = facts
        .declarations
        .iter()
        .map(|fact| fact.parameters.as_ref().map_or(0, Vec::len))
        .sum();
    let component_member_count = facts
        .declarations
        .iter()
        .filter_map(|fact| fact.component_props.as_ref())
        .map(|props| match props {
            brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::TypeMember {
                members,
                ..
            } => members.len(),
            _ => 0,
        })
        .sum();
    let property_receiver_member_count = facts
        .property_receivers
        .iter()
        .map(|fact| fact.members.len())
        .sum();
    (
        facts.bindings.len(),
        facts.exports.len(),
        facts.declarations.len(),
        type_names,
        type_children,
        type_members,
        type_parameters,
        declaration_parameters,
        component_member_count,
        facts.declaration_bindings.len(),
        facts.property_receivers.len(),
        property_receiver_member_count,
    )
}

fn encode_import_kind(kind: ImportKind) -> i64 {
    match kind {
        ImportKind::Default => 0,
        ImportKind::Named => 1,
        ImportKind::Namespace => 2,
        ImportKind::CommonJsRequire => 3,
        ImportKind::Glob => 4,
    }
}

fn encode_receiver_binding(binding: JsTsReceiverBinding) -> i64 {
    match binding {
        JsTsReceiverBinding::Unbound => 0,
        JsTsReceiverBinding::Program => 1,
        JsTsReceiverBinding::Local => 2,
    }
}

fn validate_links(facts: &JsTsSourceFacts, source: &ParsedSourceFacts) {
    for binding in &facts.bindings {
        assert!(
            binding.import.index() < source.imports.len(),
            "JS/TS binding points outside canonical imports: {:?}",
            binding.import
        );
    }
    for export in &facts.exports {
        assert!(
            export.occurrence.index() < source.occurrences.occurrence_count(),
            "JS/TS export points outside canonical occurrences: {:?}",
            export.occurrence
        );
        match &export.kind {
            JsTsExportKind::Local { .. } | JsTsExportKind::Default { .. } => {}
            JsTsExportKind::ReexportNamed { import }
            | JsTsExportKind::ReexportModule { import }
            | JsTsExportKind::Star { import } => assert!(
                import.index() < source.imports.len(),
                "JS/TS export points outside canonical imports: {import:?}"
            ),
        }
    }
    for declaration in &facts.declarations {
        assert!(
            declaration.declaration.index() < source.occurrences.declaration_count(),
            "JS/TS declaration fact points outside canonical declarations: {:?}",
            declaration.declaration
        );
        for type_id in declaration
            .alias_type
            .into_iter()
            .chain(declaration.member_type)
            .chain(declaration.declared_type)
            .chain(declaration.return_type)
            .chain(
                declaration
                    .parameters
                    .iter()
                    .flat_map(|types| types.iter().flatten().copied()),
            )
        {
            assert!(
                type_id.index() < facts.types.len(),
                "JS/TS declaration fact points outside types: {type_id:?}"
            );
        }
        if let Some(props) = &declaration.component_props {
            match props {
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Type(
                    type_id,
                )
                | brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::TypeMember {
                    owner_type: type_id,
                    ..
                } => assert!(
                    type_id.index() < facts.types.len(),
                    "JS/TS component props point outside types: {type_id:?}"
                ),
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Named(name) => {
                    assert!(!name.is_empty(), "JS/TS component props has no name");
                }
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Module(
                    import,
                ) => {
                    assert!(
                        import.index() < source.imports.len(),
                        "JS/TS component props point outside imports: {import:?}"
                    );
                }
            }
        }
    }
    for binding in &facts.declaration_bindings {
        assert!(
            binding.declaration.index() < source.occurrences.declaration_count(),
            "JS/TS declaration binding points outside declarations: {:?}",
            binding.declaration
        );
        assert!(
            binding.binder.index() < source.occurrences.occurrence_count(),
            "JS/TS declaration binding points outside occurrences: {:?}",
            binding.binder
        );
        assert!(
            !binding.name.is_empty(),
            "JS/TS declaration binding has no name"
        );
    }
    for receiver in &facts.property_receivers {
        assert!(
            receiver.declaration.index() < source.occurrences.declaration_count(),
            "JS/TS property receiver points outside declarations: {:?}",
            receiver.declaration
        );
        assert!(
            receiver.property.index() < source.occurrences.occurrence_count(),
            "JS/TS property receiver points outside occurrences: {:?}",
            receiver.property
        );
        assert!(
            !receiver.receiver_root.is_empty(),
            "JS/TS receiver has no root"
        );
        for member in &receiver.members {
            assert!(!member.is_empty(), "JS/TS receiver has an empty member");
        }
    }
    for (type_index, type_fact) in facts.types.iter().enumerate() {
        assert!(
            type_fact.occurrence.index() < source.occurrences.occurrence_count(),
            "JS/TS type fact points outside canonical occurrences: {:?}",
            type_fact.occurrence
        );
        let mut check_type = |type_id: JsTsSourceTypeId| {
            assert!(
                type_id.index() < type_index,
                "JS/TS type fact is not postorder/dense: {type_id:?} >= {type_index}"
            );
        };
        match &type_fact.shape {
            JsTsTypeShape::Named(names) => {
                assert!(!names.is_empty(), "JS/TS named type has no path components");
            }
            JsTsTypeShape::Generic { base, arguments } => {
                check_type(*base);
                arguments.iter().copied().for_each(&mut check_type);
            }
            JsTsTypeShape::Wrapped(type_id)
            | JsTsTypeShape::Query(type_id)
            | JsTsTypeShape::Array(type_id) => check_type(*type_id),
            JsTsTypeShape::Union(types)
            | JsTsTypeShape::Intersection(types)
            | JsTsTypeShape::Tuple(types) => types.iter().copied().for_each(&mut check_type),
            JsTsTypeShape::Function { parameters, result } => {
                parameters
                    .iter()
                    .flatten()
                    .copied()
                    .for_each(&mut check_type);
                if let Some(result) = result {
                    check_type(*result);
                }
            }
            JsTsTypeShape::Object(members) => {
                for (name, type_id) in members {
                    assert!(!name.is_empty(), "JS/TS object type member has no name");
                    check_type(*type_id);
                }
            }
            JsTsTypeShape::NoReceiver | JsTsTypeShape::Unknown => {}
        }
    }
}

fn insert(
    tx: &Transaction<'_>,
    blob_id: i64,
    source: &ParsedSourceFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    let Some(facts) = source.js_ts.as_ref() else {
        return Ok(());
    };
    validate_links(facts, source);
    let (logical_rows, payload_bytes) = cost(facts);
    let (
        binding_count,
        export_count,
        declaration_count,
        type_name_count,
        type_child_count,
        type_member_count,
        type_parameter_count,
        declaration_parameter_count,
        component_member_count,
        declaration_binding_count,
        property_receiver_count,
        property_receiver_member_count,
    ) = relational_counts(facts);

    let mut types = tx.prepare_cached(
        "INSERT INTO source_js_ts_types(
           blob_id, type_id, occurrence_id, kind, child_id, result_type_id
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut type_names = tx.prepare_cached(
        "INSERT INTO source_js_ts_type_names(blob_id, type_id, ordinal, name)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut type_children = tx.prepare_cached(
        "INSERT INTO source_js_ts_type_children(blob_id, type_id, ordinal, child_id)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    let mut type_members = tx.prepare_cached(
        "INSERT INTO source_js_ts_type_members(blob_id, type_id, ordinal, name, child_id)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut type_parameters = tx.prepare_cached(
        "INSERT INTO source_js_ts_type_parameters(blob_id, type_id, ordinal, child_id)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (type_id, type_fact) in facts.types.iter().enumerate() {
        check_cancelled(cancellation)?;
        let (kind, child_id, result_type_id) = match &type_fact.shape {
            JsTsTypeShape::Named(_) => (0, None, None),
            JsTsTypeShape::Generic { base, .. } => (1, Some(*base), None),
            JsTsTypeShape::Wrapped(child) => (2, Some(*child), None),
            JsTsTypeShape::Union(_) => (3, None, None),
            JsTsTypeShape::Intersection(_) => (4, None, None),
            JsTsTypeShape::Query(child) => (5, Some(*child), None),
            JsTsTypeShape::Function { result, .. } => (6, None, *result),
            JsTsTypeShape::Object(_) => (7, None, None),
            JsTsTypeShape::Array(child) => (8, Some(*child), None),
            JsTsTypeShape::Tuple(_) => (9, None, None),
            JsTsTypeShape::NoReceiver => (10, None, None),
            JsTsTypeShape::Unknown => (11, None, None),
        };
        types.execute(params![
            blob_id,
            usize_to_i64(type_id)?,
            i64::from(type_fact.occurrence.get()),
            kind,
            child_id.map(|id| i64::from(id.get())),
            result_type_id.map(|id| i64::from(id.get())),
        ])?;
        match &type_fact.shape {
            JsTsTypeShape::Named(names) => {
                for (ordinal, name) in names.iter().enumerate() {
                    type_names.execute(params![
                        blob_id,
                        usize_to_i64(type_id)?,
                        usize_to_i64(ordinal)?,
                        name
                    ])?;
                }
            }
            JsTsTypeShape::Generic { arguments, .. }
            | JsTsTypeShape::Union(arguments)
            | JsTsTypeShape::Intersection(arguments)
            | JsTsTypeShape::Tuple(arguments) => {
                for (ordinal, child) in arguments.iter().enumerate() {
                    type_children.execute(params![
                        blob_id,
                        usize_to_i64(type_id)?,
                        usize_to_i64(ordinal)?,
                        i64::from(child.get())
                    ])?;
                }
            }
            JsTsTypeShape::Function { parameters, .. } => {
                for (ordinal, child) in parameters.iter().enumerate() {
                    type_parameters.execute(params![
                        blob_id,
                        usize_to_i64(type_id)?,
                        usize_to_i64(ordinal)?,
                        child.map(|id| i64::from(id.get()))
                    ])?;
                }
            }
            JsTsTypeShape::Object(members) => {
                for (ordinal, (name, child)) in members.iter().enumerate() {
                    type_members.execute(params![
                        blob_id,
                        usize_to_i64(type_id)?,
                        usize_to_i64(ordinal)?,
                        name,
                        i64::from(child.get())
                    ])?;
                }
            }
            JsTsTypeShape::Wrapped(_)
            | JsTsTypeShape::Query(_)
            | JsTsTypeShape::Array(_)
            | JsTsTypeShape::NoReceiver
            | JsTsTypeShape::Unknown => {}
        }
    }
    drop(types);
    drop(type_names);
    drop(type_children);
    drop(type_members);
    drop(type_parameters);

    let mut bindings = tx.prepare_cached(
        "INSERT INTO source_js_ts_bindings(
           blob_id, ordinal, import_id, kind, is_static
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for (ordinal, binding) in facts.bindings.iter().enumerate() {
        check_cancelled(cancellation)?;
        bindings.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            i64::from(binding.import.get()),
            encode_import_kind(binding.kind),
            i64::from(binding.is_static),
        ])?;
    }
    drop(bindings);

    let mut exports = tx.prepare_cached(
        "INSERT INTO source_js_ts_exports(
           blob_id, ordinal, occurrence_id, name, kind, local_name, import_id, is_esm
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for (ordinal, export) in facts.exports.iter().enumerate() {
        check_cancelled(cancellation)?;
        let (kind, local_name, import) = match &export.kind {
            JsTsExportKind::Local { local_name } => (0, Some(local_name.as_str()), None),
            JsTsExportKind::Default { local_name } => (1, local_name.as_deref(), None),
            JsTsExportKind::ReexportNamed { import } => (2, None, Some(*import)),
            JsTsExportKind::ReexportModule { import } => (3, None, Some(*import)),
            JsTsExportKind::Star { import } => (4, None, Some(*import)),
        };
        exports.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            i64::from(export.occurrence.get()),
            &export.name,
            kind,
            local_name,
            import.map(|id: SourceImportId| i64::from(id.get())),
            i64::from(export.is_esm),
        ])?;
    }
    drop(exports);

    let mut declarations = tx.prepare_cached(
        "INSERT INTO source_js_ts_declarations(
           blob_id, ordinal, declaration_id, is_interface, alias_type_id,
           member_type_id, declared_type_id, return_type_id, is_global,
           component_kind, component_type_id, component_import_id, component_name, is_callable
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )?;
    for (ordinal, declaration) in facts.declarations.iter().enumerate() {
        check_cancelled(cancellation)?;
        declarations.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            i64::from(declaration.declaration.get()),
            i64::from(declaration.is_interface),
            declaration.alias_type.map(|id| i64::from(id.get())),
            declaration.member_type.map(|id| i64::from(id.get())),
            declaration.declared_type.map(|id| i64::from(id.get())),
            declaration.return_type.map(|id| i64::from(id.get())),
            i64::from(declaration.is_global),
            declaration.component_props.as_ref().map(|props| match props {
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Type(_) => 0,
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Named(_) => 1,
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Module(_) => 2,
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::TypeMember { .. } => 3,
            }),
            declaration.component_props.as_ref().and_then(|props| match props {
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Type(type_id)
                | brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::TypeMember { owner_type: type_id, .. } => Some(i64::from(type_id.get())),
                _ => None,
            }),
            declaration.component_props.as_ref().and_then(|props| match props {
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Module(import) => Some(i64::from(import.get())),
                _ => None,
            }),
            declaration.component_props.as_ref().and_then(|props| match props {
                brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::Named(name) => Some(name.as_str()),
                _ => None,
            }),
            i64::from(declaration.parameters.is_some()),
        ])?;
    }
    drop(declarations);
    let mut declaration_parameters = tx.prepare_cached(
        "INSERT INTO source_js_ts_declaration_parameters(
           blob_id, declaration_id, ordinal, type_id
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for declaration in &facts.declarations {
        if let Some(parameters) = &declaration.parameters {
            for (ordinal, type_id) in parameters.iter().enumerate() {
                check_cancelled(cancellation)?;
                declaration_parameters.execute(params![
                    blob_id,
                    i64::from(declaration.declaration.get()),
                    usize_to_i64(ordinal)?,
                    type_id.map(|id| i64::from(id.get())),
                ])?;
            }
        }
    }
    drop(declaration_parameters);
    let mut component_members = tx.prepare_cached(
        "INSERT INTO source_js_ts_component_members(
           blob_id, declaration_id, ordinal, name
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for declaration in &facts.declarations {
        if let Some(
            brokk_bifrost_core::analyzer::js_ts_facts::JsTsComponentPropsFact::TypeMember {
                members,
                ..
            },
        ) = &declaration.component_props
        {
            for (ordinal, name) in members.iter().enumerate() {
                check_cancelled(cancellation)?;
                component_members.execute(params![
                    blob_id,
                    i64::from(declaration.declaration.get()),
                    usize_to_i64(ordinal)?,
                    name,
                ])?;
            }
        }
    }
    drop(component_members);
    let mut declaration_bindings = tx.prepare_cached(
        "INSERT INTO source_js_ts_declaration_bindings(
           blob_id, ordinal, declaration_id, binder_id, name, is_program
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (ordinal, binding) in facts.declaration_bindings.iter().enumerate() {
        check_cancelled(cancellation)?;
        declaration_bindings.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            i64::from(binding.declaration.get()),
            i64::from(binding.binder.get()),
            &binding.name,
            i64::from(binding.is_program),
        ])?;
    }
    drop(declaration_bindings);
    let mut property_receivers = tx.prepare_cached(
        "INSERT INTO source_js_ts_property_receivers(
           blob_id, ordinal, declaration_id, property_id, receiver_root, binding
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut property_receiver_members = tx.prepare_cached(
        "INSERT INTO source_js_ts_property_receiver_members(
           blob_id, receiver_ordinal, ordinal, name
         ) VALUES(?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, receiver) in facts.property_receivers.iter().enumerate() {
        check_cancelled(cancellation)?;
        property_receivers.execute(params![
            blob_id,
            usize_to_i64(ordinal)?,
            i64::from(receiver.declaration.get()),
            i64::from(receiver.property.get()),
            &receiver.receiver_root,
            encode_receiver_binding(receiver.binding),
        ])?;
        for (member_ordinal, member) in receiver.members.iter().enumerate() {
            property_receiver_members.execute(params![
                blob_id,
                usize_to_i64(ordinal)?,
                usize_to_i64(member_ordinal)?,
                member,
            ])?;
        }
    }
    drop(property_receivers);
    drop(property_receiver_members);
    tx.execute(
        "INSERT INTO source_js_ts_manifests(
           blob_id, facts_version, binding_count, export_count,
           declaration_count, type_count, type_name_count, type_child_count,
           type_member_count, type_parameter_count, declaration_parameter_count,
           component_member_count, declaration_binding_count, property_receiver_count,
           property_receiver_member_count, file_is_external_module, file_is_esm,
           logical_rows, payload_bytes
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        params![
            blob_id,
            brokk_bifrost_core::analyzer::js_ts_facts::JS_TS_SOURCE_FACTS_VERSION,
            usize_to_i64(binding_count)?,
            usize_to_i64(export_count)?,
            usize_to_i64(declaration_count)?,
            usize_to_i64(facts.types.len())?,
            usize_to_i64(type_name_count)?,
            usize_to_i64(type_child_count)?,
            usize_to_i64(type_member_count)?,
            usize_to_i64(type_parameter_count)?,
            usize_to_i64(declaration_parameter_count)?,
            usize_to_i64(component_member_count)?,
            usize_to_i64(declaration_binding_count)?,
            usize_to_i64(property_receiver_count)?,
            usize_to_i64(property_receiver_member_count)?,
            i64::from(facts.file_is_external_module),
            i64::from(facts.file_is_esm),
            usize_to_i64(logical_rows)?,
            usize_to_i64(payload_bytes)?,
        ],
    )?;
    Ok(())
}
