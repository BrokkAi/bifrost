//! Coordinated JS/TS source identity and structural publication.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::js_ts_facts::*;
use brokk_bifrost_core::analyzer::model::{
    CodeUnit, ImportInfo, SignatureMetadata, StructuredImportPath,
};
use brokk_bifrost_core::analyzer::parsed_file::{
    ParsedFile, ParsedSourceFacts, SourceDeclarationMetadataLink, SourceImportFact,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceImportId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ExportIndex};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use tree_sitter::{Node, Tree};

fn declaration_name(node: Node<'_>) -> Option<Node<'_>> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration")
            .or_else(|| node.child_by_field_name("value"))
            .unwrap_or(node)
    } else {
        node
    };
    definition
        .child_by_field_name("name")
        .or_else(|| definition.child_by_field_name("key"))
        .or_else(|| {
            definition
                .child_by_field_name("left")
                .and_then(|left| left.child_by_field_name("property"))
        })
        .or_else(|| {
            matches!(
                definition.kind(),
                "identifier" | "property_identifier" | "shorthand_property_identifier"
            )
            .then_some(definition)
        })
}

/// Declaration admission receives the live syntax handle before it creates a
/// display projection. Structural extraction borrows this same arena.
pub(crate) struct JsTsParsedFile<'source> {
    parsed: ParsedFile,
    source_text: &'source str,
    pub source: PrimarySourceFactCollector<'source>,
    declaration_by_unit: HashMap<CodeUnit, SourceDeclarationId>,
    declaration_links: HashSet<(SourceDeclarationId, CodeUnit)>,
    imports: Vec<SourceImportFact>,
    generic_imports: Vec<SourceImportId>,
    js_ts: JsTsSourceFacts,
    captured_declarations: HashSet<SourceDeclarationId>,
    types: crate::type_source::JsTsTypeCollector,
    lexical_bindings: crate::syntax::JsTsLexicalBindingIndex,
    declaration_scopes: crate::scope_source::JsTsDeclarationScopeIndex<'source>,
}

impl<'source> JsTsParsedFile<'source> {
    fn new(source: &'source str, root: Node<'source>) -> Self {
        Self {
            parsed: ParsedFile::new(String::new()),
            source_text: source,
            source: PrimarySourceFactCollector::new(source),
            declaration_by_unit: HashMap::default(),
            declaration_links: HashSet::default(),
            imports: Vec::new(),
            generic_imports: Vec::new(),
            js_ts: JsTsSourceFacts::default(),
            captured_declarations: HashSet::default(),
            types: crate::type_source::JsTsTypeCollector::default(),
            // Program bindings are forward visible. Build their lexical
            // index once while the primary tree is live.
            lexical_bindings: crate::syntax::JsTsLexicalBindingIndex::build(root, source),
            declaration_scopes: crate::scope_source::JsTsDeclarationScopeIndex::new(root, source),
        }
    }

    fn capture_declaration(&mut self, unit: &CodeUnit, node: Node<'_>, name: Option<Node<'_>>) {
        let occurrence = self.source.intern_node(node);
        let name_occurrence = name.map(|name| self.source.intern_node(name));
        let declaration = self.source.declare(occurrence, name_occurrence);
        self.declaration_by_unit.insert(unit.clone(), declaration);
        if self.captured_declarations.insert(declaration) {
            let mut binding_names = HashSet::default();
            for binding in
                self.declaration_scopes
                    .declaration_bindings(node, name, &self.lexical_bindings)
            {
                let binding_name =
                    crate::syntax::slice(binding.binder, self.source_text).to_string();
                if binding_names.insert(binding_name.clone()) {
                    self.js_ts
                        .declaration_bindings
                        .push(JsTsDeclarationBindingFact {
                            declaration,
                            binder: self.source.intern_node(binding.binder),
                            name: binding_name,
                            is_program: binding.is_program,
                        });
                }
            }
            if let Some((receiver, property)) =
                crate::syntax::direct_property_definition(node, self.source_text)
            {
                let receiver_root =
                    crate::syntax::slice(receiver.root, self.source_text).to_string();
                let binding = match self
                    .lexical_bindings
                    .binding_is_program_at(&receiver_root, receiver.root.start_byte())
                {
                    Some(true) => JsTsReceiverBinding::Program,
                    Some(false) => JsTsReceiverBinding::Local,
                    None => JsTsReceiverBinding::Unbound,
                };
                self.js_ts
                    .property_receivers
                    .push(JsTsPropertyReceiverFact {
                        declaration,
                        property: self.source.intern_node(property),
                        receiver_root,
                        members: receiver
                            .members
                            .into_iter()
                            .map(|member| {
                                crate::syntax::slice(member, self.source_text).to_string()
                            })
                            .collect(),
                        binding,
                    });
            }
            let definition = if node.kind() == "export_statement" {
                node.child_by_field_name("declaration")
                    .or_else(|| node.child_by_field_name("value"))
                    .unwrap_or(node)
            } else {
                node
            };
            let definition = if matches!(
                definition.kind(),
                "lexical_declaration" | "variable_declaration"
            ) {
                name.and_then(|name| self.declaration_scopes.parent(name))
                    .filter(|parent| parent.kind() == "variable_declarator")
                    .unwrap_or(definition)
            } else {
                definition
            };
            let alias_type = (definition.kind() == "type_alias_declaration")
                .then(|| definition.child_by_field_name("value"))
                .flatten()
                .map(|node| self.capture_type(node));
            let member_type = matches!(definition.kind(), "property_signature" | "index_signature")
                .then(|| definition.child_by_field_name("type"))
                .flatten()
                .map(|node| self.capture_type(node));
            let declared_type = definition
                .child_by_field_name("type")
                .or_else(|| {
                    (definition.kind() == "interface_declaration")
                        .then(|| definition.child_by_field_name("body"))
                        .flatten()
                })
                .map(|node| self.capture_type(node));
            let callable = if definition.kind() == "variable_declarator" {
                definition.child_by_field_name("value").filter(|value| {
                    matches!(
                        value.kind(),
                        "arrow_function" | "function_expression" | "generator_function"
                    )
                })
            } else {
                matches!(
                    definition.kind(),
                    "function_declaration"
                        | "function_signature"
                        | "function_expression"
                        | "generator_function"
                        | "arrow_function"
                        | "method_definition"
                        | "method_signature"
                        | "abstract_method_signature"
                )
                .then_some(definition)
            };
            let parameters = callable.map(|callable| {
                let mut types = Vec::new();
                if let Some(parameters) = callable.child_by_field_name("parameters") {
                    let mut cursor = parameters.walk();
                    for parameter in parameters
                        .named_children(&mut cursor)
                        .filter(|parameter| parameter.kind() != "comment")
                    {
                        types.push(
                            parameter
                                .child_by_field_name("type")
                                .map(|node| self.capture_type(node)),
                        );
                    }
                } else if callable.child_by_field_name("parameter").is_some() {
                    types.push(None);
                }
                types
            });
            let return_type = callable
                .and_then(|callable| callable.child_by_field_name("return_type"))
                .map(|node| self.capture_type(node));
            let component_props = crate::graph::receiver_analysis::jsx_binding_props_source(
                definition,
                self.source_text,
            )
            .map(|props| match props {
                crate::graph::receiver_analysis::JsxPropsSource::Type(node) => {
                    JsTsComponentPropsFact::Type(self.capture_type(node))
                }
                crate::graph::receiver_analysis::JsxPropsSource::ComponentTypeName(name) => {
                    JsTsComponentPropsFact::Named(name)
                }
                crate::graph::receiver_analysis::JsxPropsSource::Module(specifier) => {
                    JsTsComponentPropsFact::Module(
                        self.add_export_import(definition, specifier, None),
                    )
                }
                crate::graph::receiver_analysis::JsxPropsSource::TypeMember {
                    owner_type,
                    members,
                } => JsTsComponentPropsFact::TypeMember {
                    owner_type: self.capture_type(owner_type),
                    members,
                },
            });
            self.js_ts.declarations.push(JsTsDeclarationFact {
                declaration,
                is_interface: definition.kind() == "interface_declaration",
                is_global: self.declaration_scopes.declaration_is_global(node),
                alias_type,
                member_type,
                declared_type,
                parameters,
                return_type,
                component_props,
            });
        }
        if self.declaration_links.insert((declaration, unit.clone())) {
            self.parsed
                .source_declaration_units
                .push((declaration, unit.clone()));
        }
    }

    fn capture_type(&mut self, node: Node<'_>) -> JsTsSourceTypeId {
        self.types.capture(
            node,
            self.source_text,
            &mut self.source,
            &mut self.js_ts.types,
        )
    }

    pub fn add_code_unit(
        &mut self,
        unit: CodeUnit,
        node: Node<'_>,
        source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        let name = declaration_name(node);
        self.add_code_unit_with_name(unit, node, name, source, parent, top_level);
    }

    pub fn add_named_code_unit(
        &mut self,
        unit: CodeUnit,
        node: Node<'_>,
        name: Node<'_>,
        source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.add_code_unit_with_name(unit, node, Some(name), source, parent, top_level);
    }

    fn add_code_unit_with_name(
        &mut self,
        unit: CodeUnit,
        node: Node<'_>,
        name: Option<Node<'_>>,
        source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.capture_declaration(&unit, node, name);
        self.parsed
            .add_code_unit(unit, node, source, parent, top_level);
    }

    pub fn add_definition_lookup_unit(&mut self, unit: CodeUnit, node: Node<'_>, source: &str) {
        self.capture_declaration(&unit, node, declaration_name(node));
        self.parsed.add_definition_lookup_unit(unit, node, source);
    }

    pub fn add_import_syntaxes(&mut self, syntaxes: Vec<crate::imports::JsTsImportSyntax<'_>>) {
        for syntax in syntaxes {
            let import = self.add_import_syntax(syntax);
            self.generic_imports.push(import);
        }
    }

    fn add_import_syntax(
        &mut self,
        syntax: crate::imports::JsTsImportSyntax<'_>,
    ) -> SourceImportId {
        let declaration = self.source.intern_node(syntax.declaration);
        let target = syntax
            .name
            .filter(|_| syntax.import.binder_span.is_some())
            .map(|node| self.source.intern_node(node));
        let alias = syntax
            .alias
            .filter(|_| syntax.import.binder_span.is_some())
            .map(|node| self.source.intern_node(node));
        self.push_import_fact(
            syntax.import,
            declaration,
            target,
            alias,
            syntax.kind.map(|kind| (kind, syntax.is_static)),
        )
    }

    fn add_export_import(
        &mut self,
        node: Node<'_>,
        module_specifier: String,
        imported_name: Option<String>,
    ) -> SourceImportId {
        let declaration = self.source.intern_node(node);
        let info = ImportInfo {
            raw_snippet: crate::model::node_text(node, self.source_text)
                .trim()
                .to_string(),
            is_wildcard: false,
            is_global: false,
            identifier: imported_name,
            alias: None,
            binder_span: None,
            path: Some(StructuredImportPath {
                segments: vec![module_specifier],
                kind: None,
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: node.start_byte(),
            }),
        };
        self.push_import_fact(info, declaration, None, None, None)
    }

    fn push_import_fact(
        &mut self,
        info: ImportInfo,
        declaration: SourceOccurrenceId,
        target: Option<SourceOccurrenceId>,
        alias: Option<SourceOccurrenceId>,
        binding: Option<(ImportKind, bool)>,
    ) -> SourceImportId {
        let import =
            SourceImportId::try_from_index(self.imports.len()).expect("JS/TS import ids fit u32");
        if let Some((kind, is_static)) = binding {
            self.js_ts.bindings.push(JsTsImportBindingFact {
                import,
                kind,
                is_static,
            });
        }
        self.imports.push(SourceImportFact::from_import(
            info,
            declaration,
            target,
            alias,
            Vec::new(),
        ));
        import
    }

    fn add_exports(&mut self, node: Node<'_>, index: ExportIndex) {
        let occurrence = self.source.intern_node(node);
        let mut named: Vec<_> = index.exports_by_name.into_iter().collect();
        named.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, entry) in named {
            let kind = match entry {
                ExportEntry::Local { local_name } => JsTsExportKind::Local { local_name },
                ExportEntry::Default { local_name } => JsTsExportKind::Default { local_name },
                ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                } => JsTsExportKind::ReexportNamed {
                    import: self.add_export_import(node, module_specifier, Some(imported_name)),
                },
                ExportEntry::ReexportedModule { module_specifier } => {
                    JsTsExportKind::ReexportModule {
                        import: self.add_export_import(node, module_specifier, None),
                    }
                }
            };
            self.js_ts.exports.push(JsTsExportFact {
                occurrence,
                is_esm: node.kind() == "export_statement",
                name: Some(name),
                kind,
            });
        }
        for star in index.reexport_stars {
            let import = self.add_export_import(node, star.module_specifier, None);
            self.js_ts.exports.push(JsTsExportFact {
                occurrence,
                is_esm: node.kind() == "export_statement",
                name: None,
                kind: JsTsExportKind::Star { import },
            });
        }
    }

    pub fn add_signature_with_metadata(
        &mut self,
        unit: CodeUnit,
        metadata: SignatureMetadata,
    ) -> usize {
        let ordinal = self
            .parsed
            .add_signature_with_metadata(unit.clone(), metadata);
        let declaration = *self
            .declaration_by_unit
            .get(&unit)
            .expect("JS/TS metadata must follow its source declaration admission");
        let link = SourceDeclarationMetadataLink {
            declaration,
            unit,
            metadata_ordinal: ordinal,
        };
        if !self.parsed.source_declaration_metadata.contains(&link) {
            self.parsed.source_declaration_metadata.push(link);
        }
        ordinal
    }
}

pub(crate) fn add_field_member_unit(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) -> CodeUnit {
    let fq = parent
        .fq()
        .clone()
        .with_pushed(segment_interner().intern(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    code_unit
}

pub(crate) fn visit_constructor_assigned_fields(
    file: &ProjectFile,
    source: &str,
    constructor: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
    is_nested_scope: impl Fn(&str) -> bool,
) {
    let mut stack = vec![constructor];
    while let Some(node) = stack.pop() {
        if node.id() != constructor.id() && is_nested_scope(node.kind()) {
            continue;
        }
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && let Some(property) = crate::model::this_member_property(left, source)
        {
            let Some(name) = crate::model::property_name_text(property, source) else {
                continue;
            };
            let code_unit =
                add_field_member_unit(file, source, property, &name, parent, top_level, parsed);
            parsed.add_signature(
                code_unit,
                crate::model::trim_statement(crate::model::node_text(node, source)),
            );
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

impl Deref for JsTsParsedFile<'_> {
    type Target = ParsedFile;
    fn deref(&self) -> &Self::Target {
        &self.parsed
    }
}
impl DerefMut for JsTsParsedFile<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parsed
    }
}

pub(crate) enum PrimaryEvent<'tree> {
    Enter {
        node: Node<'tree>,
        parent_kind: Option<&'static str>,
        depth: usize,
    },
    Exit {
        node: Node<'tree>,
    },
}

/// The primary tree has one stack-safe driver. Declaration admission, local
/// assignment state, identifier capture and structural roles share its events.
pub(crate) fn parse_primary<'source>(
    source: &'source str,
    tree: &'source Tree,
    spec: &crate::structural::JsTsStructuralSpec,
    mut event: impl FnMut(&mut JsTsParsedFile<'source>, PrimaryEvent<'source>),
) -> ParsedFile {
    let root = tree.root_node();
    let context = spec.call_site_context(root, source);
    let kinds = CompiledKinds::compile(&tree.language(), spec.kind_table());
    let mut structural = StructuralFactCollector::new(
        spec,
        source,
        &context,
        ParentIndex::new(root),
        usize::MAX,
        None,
    );
    let mut parsed = JsTsParsedFile::new(source, root);
    let mut module_value_declarators = Vec::new();
    let module_object_exports =
        crate::graph::extractor::collect_module_object_exports(root, source);
    enum Frame<'tree> {
        Enter(Node<'tree>, Option<&'static str>, usize, Option<u32>),
        Exit(Node<'tree>),
    }
    let mut stack = vec![Frame::Enter(root, None, 0, None)];
    let mut cursor = root.walk();
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(node, parent_kind, depth, parent) => {
                parsed.js_ts.file_is_external_module |=
                    crate::syntax::external_module_evidence(node, source);
                parsed.js_ts.file_is_esm |=
                    depth == 1 && matches!(node.kind(), "import_statement" | "export_statement");
                if depth == 2
                    && node.kind() == "variable_declarator"
                    && matches!(
                        parent_kind,
                        Some("lexical_declaration" | "variable_declaration")
                    )
                {
                    module_value_declarators.push(node);
                }
                let fact = if let Some(raw_kind) = kinds.kind_of(&node).filter(|kind| {
                    spec.should_extract_with_parent(node, *kind, |node| {
                        parsed.declaration_scopes.parent(node)
                    })
                }) {
                    let kind = spec.refine_kind_with_parents(
                        node,
                        raw_kind,
                        parent.map(|id| structural.normalized_kind(id)),
                        source,
                        &context,
                        structural.parents(),
                    );
                    let fact = structural
                        .enter(node, kind, parent, &mut parsed.source)
                        .expect("JS/TS structural collection is unbounded");
                    let mut sink = structural.role_sink(&mut parsed.source);
                    spec.extract_with_parent(node, kind, &mut sink, |node| {
                        parsed.declaration_scopes.parent(node)
                    });
                    structural
                        .accept_roles(fact, sink.into_parts())
                        .expect("JS/TS structural roles are unbounded");
                    Some(fact)
                } else {
                    None
                };
                crate::identifiers::collect_js_ts_identifier(
                    node,
                    source,
                    &mut parsed.parsed.type_identifiers,
                );
                if depth == 1 {
                    // File dependencies are independent of the exported names and
                    // forwarding bindings. Even `export {} from './module'` names
                    // a direct source; source-less exports name no dependency.
                    if node.kind() == "export_statement"
                        && let Some(module_specifier) =
                            crate::syntax::js_ts_statement_module_specifier(node, source)
                    {
                        let import = parsed.add_export_import(node, module_specifier, None);
                        parsed.generic_imports.push(import);
                    }
                    let mut exports = ExportIndex::empty();
                    crate::graph::extractor::collect_export_statement(
                        node,
                        source,
                        &module_object_exports,
                        &mut exports,
                    );
                    parsed.add_exports(node, exports);
                }
                event(
                    &mut parsed,
                    PrimaryEvent::Enter {
                        node,
                        parent_kind,
                        depth,
                    },
                );
                stack.push(Frame::Exit(node));
                let start = stack.len();
                stack.extend(node.named_children(&mut cursor).map(|child| {
                    Frame::Enter(child, Some(node.kind()), depth + 1, fact.or(parent))
                }));
                stack[start..].reverse();
            }
            Frame::Exit(node) => {
                event(&mut parsed, PrimaryEvent::Exit { node });
            }
        }
    }
    let imports = crate::syntax::JsTsImportBinder::from_live_source_facts_with_lexical_bindings(
        &parsed.js_ts,
        &parsed.imports,
        &parsed.source,
        root,
        parsed.lexical_bindings.clone(),
    );
    for syntax in crate::syntax::type_argument_module_value_import_syntaxes(
        &module_value_declarators,
        source,
        &imports,
    ) {
        parsed.add_import_syntax(syntax);
    }
    let structural = structural
        .finish(root)
        .expect("JS/TS structural collection must finish");
    let occurrences = parsed.source.finish();
    let generic_imports = parsed.generic_imports;
    parsed.parsed.imports = generic_imports
        .iter()
        .map(|id| parsed.imports[id.index()].import_info(&occurrences))
        .collect();
    parsed.parsed.source_facts = Some(ParsedSourceFacts {
        cpp: None,
        js_ts: Some(parsed.js_ts),
        go: None,
        java: None,
        php: None,
        scala: None,
        ruby: None,
        python: None,
        source_bytes: source.len(),
        occurrences,
        structural,
        native_site_occurrences: Vec::new(),
        native_declaration_sources: Vec::new(),
        declaration_visibilities: None,
        rust_declaration_properties: Vec::new(),
        rust_modules: None,
        rust_types: Vec::new(),
        rust_items: Default::default(),
        imports: parsed.imports,
        generic_imports,
        rust_import_contexts: Vec::new(),
    });
    parsed.parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Parser;

    fn parse(source: &str, extension: &str) -> ParsedFile {
        let file = ProjectFile::new(std::env::temp_dir(), format!("primary.{extension}"));
        let mut parser = Parser::new();
        let language = if extension == "js" {
            tree_sitter_javascript::LANGUAGE.into()
        } else if extension == "tsx" {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        };
        parser.set_language(&language).expect("grammar");
        let tree = parser.parse(source, None).expect("tree");
        if extension == "js" {
            crate::javascript::parse_javascript_file(&file, source, &tree)
        } else {
            crate::typescript::parse_typescript_file(&file, source, &tree)
        }
    }

    #[test]
    #[hardwon(
        "#3843: source-bearing re-exports were absent from the generic file dependency projection"
    )]
    fn reexport_file_dependencies_do_not_bind_exported_names() {
        for extension in ["js", "ts", "tsx"] {
            let type_exports = if extension == "js" {
                ""
            } else {
                "export type { Shape } from './types';\nexport { type Shape } from './inline-types';\n"
            };
            let parsed = parse(
                &format!(
                    "export {{ original as renamed }} from './named';\n\
                 export * from './star';\n\
                 export * as namespace from './namespace';\n\
                 export {{}} from './empty';\n\
                 const local = 1; export {{ local }};\n\
                 export const sourceLess = './not-a-source';\n{type_exports}"
                ),
                extension,
            );
            let paths: Vec<_> = parsed
                .imports
                .iter()
                .map(|import| import.path.as_ref().expect("source path").segments.clone())
                .collect();
            let mut expected = vec![
                vec!["./named"],
                vec!["./star"],
                vec!["./namespace"],
                vec!["./empty"],
            ];
            if extension != "js" {
                expected.extend([vec!["./types"], vec!["./inline-types"]]);
            }
            assert_eq!(paths, expected);
            assert!(parsed.imports.iter().all(|import| {
                import.identifier.is_none()
                    && import.alias.is_none()
                    && import.binder_span.is_none()
                    && !import.is_wildcard
            }));
            let source = parsed.source_facts.expect("canonical source facts");
            let js_ts = source.js_ts.expect("JS/TS facts");
            assert!(js_ts.bindings.is_empty());
            assert!(js_ts.exports.iter().any(|export| {
                export.name.as_deref() == Some("renamed")
                    && matches!(export.kind, JsTsExportKind::ReexportNamed { import }
                        if !source.generic_imports.contains(&import))
            }));
        }
    }

    #[test]
    #[hardwon("#2369: deeply nested loops caused quadratic parent walks")]
    fn deeply_nested_loop_primary_capture_stays_linear() {
        // Same AST shape and depth as the production #2369 analyzer fixture;
        // this focused gate also exercises the coordinated structural capture.
        let mut source = String::from("let counter = 0;\n");
        for level in 0..16_000 {
            source.push_str("for (let i = 0; i < 1; i++) ");
            if level % 4 == 3 {
                source.push('\n');
            }
        }
        source.push_str("counter++;\n");
        let started = std::time::Instant::now();
        let parsed = parse(&source, "js");
        let facts = parsed.source_facts.as_ref().expect("primary facts");
        assert!(
            parsed
                .source_declaration_units
                .iter()
                .any(|(_, unit)| unit.identifier() == "counter")
        );
        assert_eq!(
            facts
                .structural
                .nodes()
                .iter()
                .filter(|node| node.kind
                    == brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Loop)
                .count(),
            16_000
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(60));
    }
}
