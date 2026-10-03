//! Coordinated JS/TS source identity and structural publication.

use brokk_bifrost_core::analyzer::js_ts_facts::*;
use brokk_bifrost_core::analyzer::model::{
    CodeUnit, ImportInfo, SignatureMetadata, StructuredImportPath,
};
use brokk_bifrost_core::analyzer::parsed_file::{
    ParsedFile, ParsedSourceFacts, SourceDeclarationMetadataLink, SourceImportFact,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceImportId,
};
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
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
        self.capture_declaration(&unit, node, name);
        self.parsed
            .add_code_unit(unit, node, source, parent, top_level);
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
        self.capture_declaration(&unit, node, Some(name));
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
        let import =
            SourceImportId::try_from_index(self.imports.len()).expect("JS/TS import ids fit u32");
        if let Some(kind) = syntax.kind {
            self.js_ts.bindings.push(JsTsImportBindingFact {
                import,
                kind,
                is_static: syntax.is_static,
            });
        }
        self.imports.push(SourceImportFact::from_import(
            syntax.import,
            declaration,
            target,
            alias,
            Vec::new(),
        ));
        import
    }

    fn add_export_import(
        &mut self,
        node: Node<'_>,
        module_specifier: String,
        imported_name: Option<String>,
    ) -> SourceImportId {
        let declaration = self.source.intern_node(node);
        let import =
            SourceImportId::try_from_index(self.imports.len()).expect("JS/TS import ids fit u32");
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
        self.imports.push(SourceImportFact::from_import(
            info,
            declaration,
            None,
            None,
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
                    let kind = spec.refine_kind(
                        node,
                        raw_kind,
                        parent.map(|id| structural.normalized_kind(id)),
                        source,
                        &context,
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
        .finish()
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

    #[test]
    fn declaration_and_structural_projections_share_live_node_identity() {
        for extension in ["js", "ts", "tsx"] {
            let source = "export class Widget { render(value) { return value; } }";
            let parsed = parse(source, extension);
            let facts = parsed.source_facts.as_ref().expect("canonical publication");
            assert_eq!(facts.source_bytes, source.len());
            let mut matched_methods = 0;
            for (declaration, unit) in &parsed.source_declaration_units {
                if unit.identifier() != "render" {
                    continue;
                }
                matched_methods += 1;
                let declaration = facts.occurrences.declaration(*declaration);
                assert!(
                    facts
                        .structural
                        .nodes()
                        .iter()
                        .any(|node| node.occurrence == declaration.occurrence)
                );
                let name = facts
                    .occurrences
                    .occurrence(declaration.name.expect("method name"))
                    .range;
                assert_eq!(&source[name.start_byte..name.end_byte], "render");
            }
            assert_eq!(matched_methods, 1);
            assert!(!parsed.source_declaration_metadata.is_empty());
        }
    }

    #[test]
    fn destructured_binders_share_statement_but_keep_distinct_names() {
        let source = "export const { first, second: renamed } = object;";
        let parsed = parse(source, "ts");
        let facts = parsed.source_facts.as_ref().expect("canonical publication");
        let declarations: Vec<_> = parsed
            .source_declaration_units
            .iter()
            .filter(|(_, unit)| matches!(unit.identifier(), "first" | "renamed"))
            .map(|(id, _)| facts.occurrences.declaration(*id))
            .collect();
        assert_eq!(declarations.len(), 2);
        assert_eq!(declarations[0].occurrence, declarations[1].occurrence);
        assert_ne!(declarations[0].name, declarations[1].name);
    }

    #[test]
    fn exports_keep_source_only_imports_out_of_generic_projection() {
        let parsed = parse(
            "import { a as local } from './a'; export { local as publicName }; export * from './b';",
            "ts",
        );
        let facts = parsed.source_facts.as_ref().expect("canonical publication");
        let js_ts = facts.js_ts.as_ref().expect("JS/TS family");
        assert_eq!(parsed.imports.len(), 1);
        assert_eq!(js_ts.bindings.len(), 1);
        assert_eq!(js_ts.exports.len(), 2);
        assert_eq!(facts.imports.len(), 2);
        assert_eq!(facts.generic_imports.len(), 1);
    }

    #[test]
    fn type_annotations_capture_structure_and_direct_declaration_links() {
        let parsed = parse(
            "interface Props { title: string } type Wrapped<T = Props> = Promise<T>; export function run(cb: (props: Props) => void): Wrapped<Props> { return null; }",
            "ts",
        );
        let source = parsed.source_facts.as_ref().expect("source facts");
        let facts = source.js_ts.as_ref().expect("JS/TS family");
        let declaration = |name| {
            let (id, _) = parsed
                .source_declaration_units
                .iter()
                .find(|(_, unit)| unit.identifier() == name)
                .expect("published declaration");
            facts
                .declarations
                .iter()
                .find(|declaration| declaration.declaration == *id)
                .expect("typed declaration")
        };
        assert!(declaration("Props").is_interface);
        assert!(matches!(
            facts.types[declaration("Wrapped")
                .alias_type
                .expect("alias value")
                .index()]
            .shape,
            JsTsTypeShape::Generic { .. }
        ));
        let run = declaration("run");
        let parameter =
            run.parameters.as_ref().expect("callable parameters")[0].expect("parameter annotation");
        let JsTsTypeShape::Wrapped(callback) = facts.types[parameter.index()].shape else {
            panic!("annotation wrapper");
        };
        let JsTsTypeShape::Function { parameters, .. } = &facts.types[callback.index()].shape
        else {
            panic!("callback shape");
        };
        assert_eq!(parameters.len(), 1);
        assert!(parameters[0].is_some());
        assert!(run.return_type.is_some());
    }

    #[test]
    fn direct_properties_capture_program_local_and_unbound_receivers() {
        let source = "const Tools = { parse(value) { return value; } }; window.Shared = function() {}; function outer() { const local = {}; local.run = function() {}; }";
        let parsed = parse(source, "js");
        let publication = parsed.source_facts.as_ref().expect("source facts");
        let facts = publication.js_ts.as_ref().expect("JS/TS family");
        for (root, expected) in [
            ("Tools", JsTsReceiverBinding::Program),
            ("window", JsTsReceiverBinding::Unbound),
            ("local", JsTsReceiverBinding::Local),
        ] {
            let receiver = facts
                .property_receivers
                .iter()
                .find(|receiver| receiver.receiver_root == root)
                .unwrap_or_else(|| {
                    panic!("missing receiver {root}: {:?}", facts.property_receivers)
                });
            assert_eq!(receiver.binding, expected);
            assert_eq!(
                publication
                    .occurrences
                    .declaration(receiver.declaration)
                    .name,
                Some(receiver.property)
            );
            assert!(
                parsed
                    .source_declaration_units
                    .iter()
                    .any(|(declaration, _)| *declaration == receiver.declaration)
            );
            let property = publication.occurrences.occurrence(receiver.property);
            assert!(!source[property.range.start_byte..property.range.end_byte].is_empty());
        }
        assert!(!facts.file_is_external_module);
        let module = parse("function load() { return require('./nested'); }", "js");
        assert!(
            module
                .source_facts
                .as_ref()
                .unwrap()
                .js_ts
                .as_ref()
                .unwrap()
                .file_is_external_module
        );
    }

    #[test]
    fn type_argument_module_values_are_canonical_source_only_imports() {
        let source_text = "import * as M from './module';\nconst before = actual;\nconst actual = importActual<typeof M>('./module');\nconst after = actual;\n";
        let parsed = parse(source_text, "ts");
        let source = parsed.source_facts.as_ref().expect("source facts");
        let facts = source.js_ts.as_ref().expect("JS/TS family");
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        let tree = parser.parse(source_text, None).expect("tree");
        let binder = crate::syntax::JsTsImportBinder::from_source_facts_with_lexical_bindings(
            facts,
            &source.imports,
            &source.occurrences,
            tree.root_node(),
            crate::syntax::JsTsLexicalBindingIndex::build(tree.root_node(), source_text),
        );
        assert_eq!(
            binder
                .binding("actual")
                .expect("type argument binding")
                .module_specifier,
            "./module"
        );
        let before_use = source_text
            .find("const before = actual;")
            .expect("before use")
            + "const before = ".len();
        assert!(matches!(
            binder.binding_at("actual", before_use),
            crate::syntax::JsTsImportBindingResolution::Inactive
        ));
        let after_use = source_text
            .find("const after = actual;")
            .expect("after use")
            + "const after = ".len();
        let crate::syntax::JsTsImportBindingResolution::Exact(actual) =
            binder.binding_at("actual", after_use)
        else {
            panic!("typed module value should resolve after its initializer");
        };
        assert_eq!(actual.binding.module_specifier, "./module");
        let type_query = source_text.find("typeof M").expect("type query") + "typeof ".len();
        assert!(matches!(
            binder.binding_at("M", type_query),
            crate::syntax::JsTsImportBindingResolution::Exact(_)
        ));
        assert_eq!(parsed.imports.len(), 1);
        assert_eq!(source.imports.len(), 2);
    }
}
