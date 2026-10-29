use crate::structural::{CSHARP_KIND_TABLE, CSHARP_STRUCTURAL_SPEC};
use brokk_bifrost_core::analyzer::common::{IdentifierSigil, node_source_text as cs_node_text};
use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentKind, joined_segments, segment_interner,
};
use brokk_bifrost_core::analyzer::model::StructuredTypeIdentityBuilder;
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CallableOverrideModifier, ClassLikeKind, CodeUnitType, DispatchExtensibility,
    ParameterMetadata, Range, SignatureMetadata, StructuredTypeIdentity, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::parsed_file::{
    CSharpSemanticDeclaration, CSharpSemanticDeclarationKind, ParsedFile, ParsedSourceFacts,
    SourceImportFact,
};
use brokk_bifrost_core::analyzer::source_facts::{PrimarySourceFactCollector, SourceImportId};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::child_by_field_or_first_named_child;
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    ParentIndex, child_by_field_or_named_child_of_kinds, first_named_child_of_kind, node_range,
};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

use crate::imports::csharp_import_info_from_using_directive;
use crate::syntax::{
    csharp_attribute_type_names, csharp_constant_pattern_type_candidate,
    csharp_default_member_visibility, csharp_has_modifier, csharp_identifier_text as cs_ident_text,
    csharp_member_access_type_receiver, csharp_type_node_identity, csharp_type_reference_root,
};
use crate::test_detection::csharp_method_has_runnable_test_attribute;

/// Whether `kind` is tree-sitter-c-sharp's identifier leaf kind. C# spells its
/// verbatim-identifier escape as a leading `@` (`@class`), carried verbatim in
/// the `identifier` token text; no other node kind carries an `@` that denotes
/// an identifier (verbatim strings are `verbatim_string_literal`, interpolated
/// strings and attributes are their own kinds), so gating here keeps the sigil
/// strip off those spans.
fn csharp_identifier_like_node_kind(kind: &str) -> bool {
    kind == "identifier"
}

/// tree-sitter-c-sharp verbatim-identifier normalization (`@class` -> `class`),
/// gated to the identifier leaf kind. This is the same normalization the
/// declaration side already applies when building short/fq names, shared here so
/// the reference/get-definition side agrees (previously it did not — issue-1128
/// class inconsistency).
pub const CSHARP_IDENTIFIER_SIGIL: IdentifierSigil = IdentifierSigil {
    is_identifier_kind: csharp_identifier_like_node_kind,
    prefix: "@",
};

/// Build the structured namespace-path prefix for a C# declaration.
///
/// `scope.package_name` (built by `csharp_join_namespace`) is already the
/// `.`-joined dotted namespace path; C# identifiers can never contain a
/// literal `.`, so splitting on `.` is lossless. Each component becomes one
/// [`SegmentKind::Package`] segment, mirroring java/python's `Package`-tagged
/// (not `Path`-tagged) namespace/module prefixes.
fn csharp_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in joined_segments(package_name, ".") {
        fq.push(segment_interner().intern(component, SegmentKind::Package));
    }
    fq
}

pub fn parse_csharp_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    parse_csharp_file_with_step(file, source, tree, |_, _| Default::default())
}

/// Coordinated declaration and lexical-fact extraction for the native trial.
pub fn parse_csharp_file_with_native_facts(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> ParsedFile {
    parse_csharp_file_with_step(file, source, tree, |parsed, collector| {
        let mut bridges = crate::resolution::SourceBridges::default();
        parsed.resolution_facts = crate::resolution::produce(
            tree,
            source,
            &crate::preprocessor::scan_preprocessor(source),
            collector,
            &mut bridges,
        );
        bridges
    })
}

fn parse_csharp_file_with_step<'s>(
    file: &ProjectFile,
    source: &'s str,
    tree: &Tree,
    native_step: impl FnOnce(
        &mut ParsedFile,
        &mut PrimarySourceFactCollector<'s>,
    ) -> crate::resolution::SourceBridges,
) -> ParsedFile {
    let mut parsed = ParsedFile::new(String::new());
    parsed.contains_tests = Some(false);
    let root = tree.root_node();
    let ancestry = ParentIndex::unindexed();
    let grammar = tree_sitter_c_sharp::LANGUAGE.into();
    let kinds = CompiledKinds::compile(&grammar, CSHARP_KIND_TABLE);
    let context = CSHARP_STRUCTURAL_SPEC.call_site_context(root, source);
    let mut structural = StructuralFactCollector::new(
        &CSHARP_STRUCTURAL_SPEC,
        source,
        &context,
        ParentIndex::unindexed(),
        usize::MAX,
        None,
    );
    let mut visitor = CSharpVisitor {
        file,
        source,
        ancestry,
        parsed: &mut parsed,
        source_facts: PrimarySourceFactCollector::new(source),
        source_imports: Vec::new(),
        current_is_test_method: false,
        current_properties: CSharpDeclarationProperties::default(),
    };
    // Declaration admission preserves the existing namespace/type-container
    // rules. Every node still enters structural and type-identifier extraction,
    // including bodies and malformed syntax omitted by declaration admission.
    let mut declarations = Vec::new();
    visitor.push_children(
        root,
        CSharpScope {
            package_name: String::new(),
            lexical_scope: Vec::new(),
            enclosing_type: None,
        },
        &mut declarations,
    );
    let mut pending: HashMap<_, _> = declarations
        .drain(..)
        .map(|work| {
            let node = match &work {
                CSharpWork::Node { node, .. } | CSharpWork::RecoveredMember { node, .. } => node,
            };
            (node.id(), work)
        })
        .collect();
    let mut stack = vec![(root, None)];
    while let Some((node, enclosing)) = stack.pop() {
        collect_csharp_type_identifier(node, source, &mut visitor.parsed.type_identifiers);
        visitor.current_is_test_method = csharp_method_has_runnable_test_attribute(node, source);
        if visitor.current_is_test_method {
            visitor.parsed.contains_tests = Some(true);
        }
        let work = pending.remove(&node.id());
        let scope = work.as_ref().map(|work| match work {
            CSharpWork::Node { scope, .. } | CSharpWork::RecoveredMember { scope, .. } => scope,
        });
        visitor.current_properties = CSharpDeclarationProperties::capture(
            node,
            source,
            scope
                .as_ref()
                .map(|scope| scope.lexical_scope.as_slice())
                .unwrap_or_default(),
        );
        if let Some(work) = work {
            match work {
                CSharpWork::Node { node, scope } => {
                    visitor.visit_node(node, &scope, &mut declarations)
                }
                CSharpWork::RecoveredMember { node, scope } => {
                    visitor.visit_recovered_member(node, &scope)
                }
            }
            pending.extend(declarations.drain(..).map(|work| {
                let node = match &work {
                    CSharpWork::Node { node, .. } | CSharpWork::RecoveredMember { node, .. } => {
                        node
                    }
                };
                (node.id(), work)
            }));
        }
        visitor.capture_semantic_declaration(node);
        structural.record_children(node);
        let mut structural_parent = enclosing;
        if node.is_named()
            && let Some(kind) = kinds.kind_of(&node)
            && CSHARP_STRUCTURAL_SPEC.should_extract(node, kind)
        {
            let kind = CSHARP_STRUCTURAL_SPEC.refine_kind(
                node,
                kind,
                enclosing.map(|id| structural.normalized_kind(id)),
                source,
                &context,
            );
            let id = structural
                .enter(node, kind, enclosing, &mut visitor.source_facts)
                .expect("complete C# preparation has no structural admission limit");
            let mut sink = structural.role_sink(&mut visitor.source_facts);
            CSHARP_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
            structural
                .accept_roles(id, sink.into_parts())
                .expect("complete C# preparation has no structural admission limit");
            structural_parent = Some(id);
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                visitor.ancestry.record_parent(child, node);
                stack.push((child, structural_parent));
            }
        }
    }
    assert!(
        pending.is_empty(),
        "C# declaration events must belong to the primary tree"
    );
    let bridges = native_step(visitor.parsed, &mut visitor.source_facts);
    let occurrences = visitor.source_facts.finish();
    let imports = visitor.source_imports;
    parsed.imports = imports
        .iter()
        .map(|import| import.import_info(&occurrences))
        .collect();
    parsed.source_facts = Some(ParsedSourceFacts {
        cpp: None,
        go: None,
        java: None,
        js_ts: None,
        php: None,
        scala: None,
        ruby: None,
        python: None,
        source_bytes: source.len(),
        occurrences,
        structural: structural
            .finish(root)
            .expect("complete C# structural facts"),
        native_site_occurrences: bridges.occurrences,
        native_declaration_sources: bridges.declarations,
        declaration_visibilities: None,
        rust_declaration_properties: Vec::new(),
        rust_modules: None,
        rust_types: Vec::new(),
        rust_items: Default::default(),
        generic_imports: (0..imports.len())
            .map(|index| SourceImportId::try_from_index(index).expect("C# import ids fit u32"))
            .collect(),
        imports,
        rust_import_contexts: Vec::new(),
    });
    parsed
}

/// The type declaration whose body is currently being walked.
#[derive(Clone)]
struct CSharpEnclosingType<'tree> {
    declaration: Node<'tree>,
    unit: CodeUnit,
    /// The type declaration's own `name` field text, exactly as written. This is
    /// neither `unit.short_name()` (which carries the `Outer$` nesting prefix)
    /// nor the identity name (which carries the generic-arity suffix, so that
    /// `class Box<T>` is spelled ``Box`1``), so it is the only spelling a
    /// `constructor_declaration`'s name can be compared against.
    declared_name: String,
}

#[derive(Clone)]
struct CSharpScope<'tree> {
    package_name: String,
    lexical_scope: Vec<String>,
    enclosing_type: Option<CSharpEnclosingType<'tree>>,
}

/// One node the declaration walk still owes a visit.
enum CSharpWork<'tree> {
    /// A node visited in the scope its lexical position gives it.
    Node {
        node: Node<'tree>,
        scope: CSharpScope<'tree>,
    },
    /// A member declaration parser recovery detached from a type body, visited
    /// in the member scope of the type that really owns it. See
    /// [`CSharpVisitor::truncated_type_member_scope`].
    RecoveredMember {
        node: Node<'tree>,
        scope: CSharpScope<'tree>,
    },
}

#[derive(Default)]
struct CSharpDeclarationProperties {
    return_type_text: Option<String>,
    display_type_text: Option<String>,
    return_type_identity: Option<StructuredTypeIdentity>,
    semantic_type_spelling: Option<String>,
    is_static: bool,
    is_const: bool,
    is_readonly: bool,
}

impl CSharpDeclarationProperties {
    fn capture(node: Node<'_>, source: &str, lexical_scope: &[String]) -> Self {
        if !matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "property_declaration"
                | "event_declaration"
                | "field_declaration"
                | "event_field_declaration"
                | "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) {
            return Self::default();
        }
        let type_node = if matches!(node.kind(), "field_declaration" | "event_field_declaration") {
            first_named_child_of_kind(node, "variable_declaration")
                .and_then(|declaration| declaration.child_by_field_name("type"))
        } else {
            csharp_declared_type_node(node)
        };
        let return_type_text = type_node
            .map(|ty| csharp_type_node_identity(ty, source))
            .filter(|text| !text.is_empty());
        let display_type_text = type_node.map(|ty| csharp_render_node(ty, source));
        let return_type_identity =
            type_node.and_then(|ty| csharp_structured_type_identity(ty, source, lexical_scope));
        let semantic_type_spelling = type_node.and_then(|ty| {
            crate::syntax::csharp_declared_type_spelling(ty, return_type_text.as_deref()?)
        });
        Self {
            return_type_text,
            display_type_text,
            return_type_identity,
            semantic_type_spelling,
            is_static: csharp_has_modifier(source, node, "static"),
            is_const: csharp_has_modifier(source, node, "const"),
            is_readonly: csharp_has_modifier(source, node, "readonly"),
        }
    }
}

struct CSharpVisitor<'context, 'source, 'tree> {
    file: &'context ProjectFile,
    source: &'source str,
    ancestry: ParentIndex<'tree>,
    parsed: &'context mut ParsedFile,
    source_facts: PrimarySourceFactCollector<'source>,
    source_imports: Vec<SourceImportFact>,
    current_is_test_method: bool,
    current_properties: CSharpDeclarationProperties,
}

impl CSharpVisitor<'_, '_, '_> {
    fn capture_semantic_declaration(&mut self, node: Node<'_>) {
        let kind = match node.kind() {
            "method_declaration" if self.current_properties.is_static => {
                CSharpSemanticDeclarationKind::StaticMethodReturn
            }
            "method_declaration" => CSharpSemanticDeclarationKind::InstanceMethodReturn,
            "field_declaration"
            | "event_field_declaration"
            | "property_declaration"
            | "event_declaration" => CSharpSemanticDeclarationKind::Member,
            _ => return,
        };
        let mut current = self.ancestry.parent(node);
        let mut owner = None;
        let mut namespace = Vec::new();
        let mut nested_type = false;
        while let Some(parent) = current {
            if matches!(
                parent.kind(),
                "class_declaration"
                    | "interface_declaration"
                    | "struct_declaration"
                    | "enum_declaration"
                    | "record_declaration"
                    | "record_struct_declaration"
            ) {
                if owner.is_none() {
                    owner = parent.child_by_field_name("name");
                } else {
                    nested_type = true;
                }
            }
            if matches!(
                parent.kind(),
                "namespace_declaration" | "file_scoped_namespace_declaration"
            ) && let Some(name) = parent.child_by_field_name("name")
            {
                namespace.push(cs_node_text(name, self.source).to_owned());
            }
            current = self.ancestry.parent(parent);
        }
        let Some(owner) = owner else {
            return;
        };
        if nested_type && kind == CSharpSemanticDeclarationKind::StaticMethodReturn {
            return;
        }
        let owner = cs_node_text(owner, self.source).to_owned();
        namespace.reverse();
        let declarations = if matches!(node.kind(), "field_declaration" | "event_field_declaration")
        {
            first_named_child_of_kind(node, "variable_declaration")
                .map(|declaration| {
                    let mut cursor = declaration.walk();
                    declaration
                        .named_children(&mut cursor)
                        .filter(|child| child.kind() == "variable_declarator")
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            vec![node]
        };
        for declaration in declarations {
            let Some(name) = declaration
                .child_by_field_name("name")
                .or_else(|| declaration.named_child(0))
            else {
                continue;
            };
            if cs_node_text(name, self.source).is_empty() {
                continue;
            }
            let declaration = self.source_facts.declare_node(declaration, Some(name));
            self.parsed
                .csharp_semantic_declarations
                .push(CSharpSemanticDeclaration {
                    declaration,
                    namespace: namespace.clone(),
                    owner: owner.clone(),
                    kind,
                    is_static: self.current_properties.is_static
                        || self.current_properties.is_const,
                    type_spelling: self.current_properties.semantic_type_spelling.clone(),
                });
        }
    }

    fn add_source_signature(
        &mut self,
        node: Node<'_>,
        unit: CodeUnit,
        metadata: SignatureMetadata,
    ) {
        let declaration = self
            .source_facts
            .declare_node(node, node.child_by_field_name("name"));
        self.parsed
            .source_declaration_units
            .push((declaration, unit.clone()));
        self.parsed
            .add_signature_with_source_declaration_metadata(declaration, unit, metadata);
    }

    fn push_children<'tree>(
        &self,
        node: Node<'tree>,
        scope: CSharpScope<'tree>,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        // A file-scoped namespace (`namespace X;`) has no body: its type declarations
        // are following SIBLINGS, not children. Apply its namespace to everything after
        // it so their package_name is populated. Block namespaces keep a body and flow
        // through `queue_namespace`.
        let mut current = scope;
        let mut scoped: Vec<CSharpWork<'tree>> = Vec::with_capacity(children.len());
        // The type declaration a following `global_statement` would belong to
        // if parser recovery truncated it, read through
        // `truncated_type_member_scope` only when such a statement actually
        // arrives. Only a declaration container resets it: recovery leaves
        // stray `}` ERROR siblings between the statements it detached, and
        // those say nothing about ownership.
        let mut preceding_type: Option<Node<'tree>> = None;
        for child in children {
            match child.kind() {
                "file_scoped_namespace_declaration" => {
                    if let Some(namespace_path) = self.namespace_scope_path(child) {
                        let package_name =
                            csharp_join_namespace(&current.package_name, &namespace_path);
                        let mut lexical_scope = current.lexical_scope.clone();
                        lexical_scope.extend(namespace_path);
                        current = CSharpScope {
                            package_name,
                            lexical_scope,
                            enclosing_type: current.enclosing_type.clone(),
                        };
                    }
                    preceding_type = None;
                    continue;
                }
                "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "record_struct_declaration" => preceding_type = Some(child),
                "namespace_declaration" => preceding_type = None,
                "global_statement" => {
                    if let Some(owner) = preceding_type
                        && let Some(member) = csharp_recovered_type_member(child)
                        && let Some(member_scope) =
                            self.truncated_type_member_scope(owner, &current)
                    {
                        scoped.push(CSharpWork::RecoveredMember {
                            node: member,
                            scope: member_scope,
                        });
                        continue;
                    }
                }
                _ => {}
            }
            scoped.push(CSharpWork::Node {
                node: child,
                scope: current.clone(),
            });
        }
        for work in scoped.into_iter().rev() {
            stack.push(work);
        }
    }

    /// The member scope of `node` when parser recovery truncated its body, or
    /// `None` when the body parsed cleanly.
    ///
    /// C# permits top-level statements only before the file's type and
    /// namespace declarations, and forbids them outright in a file with a
    /// file-scoped namespace, so a `global_statement` that follows a type whose
    /// own subtree carries a parse error is the remainder of that type's body
    /// rather than a program entry point. The scope this returns is the same
    /// one [`Self::visit_type_declaration`] builds for the members that stayed
    /// inside the body, so an adopted member is indexed exactly as its
    /// surviving siblings are.
    ///
    /// What this cannot repair (#3326): only declarations recovery re-emits as
    /// whole statements come back here. Statements inside the method that
    /// triggered recovery stay `ERROR` soup, and a detached field, property,
    /// constructor or nested type keeps whatever top-level shape recovery gave
    /// it. `brokk-tree-sitter-c-sharp` 0.23.7 fixes the known `partial` and
    /// `required` assignment trigger at the grammar layer; this fallback remains
    /// for other malformed or unsupported source.
    fn truncated_type_member_scope<'tree>(
        &self,
        node: Node<'tree>,
        scope: &CSharpScope<'tree>,
    ) -> Option<CSharpScope<'tree>> {
        if !node.has_error() {
            return None;
        }
        let (unit, declared_name, identity_name) =
            csharp_type_code_unit(self.file, self.source, node, scope)?;
        let mut lexical_scope = scope.lexical_scope.clone();
        lexical_scope.push(identity_name);
        Some(CSharpScope {
            package_name: scope.package_name.clone(),
            lexical_scope,
            enclosing_type: Some(CSharpEnclosingType {
                declaration: node,
                unit,
                declared_name,
            }),
        })
    }

    /// Index a member declaration parser recovery detached from its type body.
    ///
    /// The member is indexed exactly as if it had stayed in the body, and the
    /// owner's recorded range grows to contain it: a container that adopts a
    /// member must contain it (#3291).
    fn visit_recovered_member(&mut self, node: Node<'_>, scope: &CSharpScope<'_>) {
        let owner = &scope
            .enclosing_type
            .as_ref()
            .expect("a recovered member carries the member scope of the type that owns it")
            .unit;
        if self.visit_method(node, scope).is_some() {
            self.parsed
                .extend_declaration_range(owner, node_range(node));
        }
    }

    fn namespace_scope_path(&self, node: Node<'_>) -> Option<Vec<String>> {
        csharp_namespace_path_from_declaration(node, self.source)
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope<'tree>,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        match node.kind() {
            // Block namespaces only; file-scoped namespaces are handled in push_children
            // (their types are following siblings, not body children).
            "namespace_declaration" => self.queue_namespace(node, scope, stack),
            "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "record_struct_declaration" => self.visit_type_declaration(node, scope, stack),
            "method_declaration" => {
                self.visit_method(node, scope);
            }
            "constructor_declaration" => self.visit_constructor(node, scope),
            "property_declaration" => self.visit_property(node, scope),
            "field_declaration" => self.visit_field_declaration(node, scope),
            "enum_member_declaration" => self.visit_enum_member(node, scope),
            "using_directive" => self.visit_using_directive(node),
            _ => {}
        }
    }

    fn visit_using_directive(&mut self, node: Node<'_>) {
        let raw = cs_node_text(node, self.source).trim().to_string();
        if raw.is_empty() {
            return;
        }
        if let Some(info) = csharp_import_info_from_using_directive(node, self.source, raw) {
            let declaration = self.source_facts.intern_node(node);
            let alias = node
                .child_by_field_name("name")
                .map(|alias| self.source_facts.intern_node(alias));
            self.source_imports.push(SourceImportFact::from_import(
                info,
                declaration,
                None,
                alias,
                Vec::new(),
            ));
        }
    }

    fn queue_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope<'tree>,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let Some(namespace_path) = self.namespace_scope_path(node) else {
            return;
        };
        let package_name = csharp_join_namespace(&scope.package_name, &namespace_path);
        let mut lexical_scope = scope.lexical_scope.clone();
        lexical_scope.extend(namespace_path);
        if let Some(body) = cs_namespace_body(node) {
            self.push_children(
                body,
                CSharpScope {
                    package_name,
                    lexical_scope,
                    enclosing_type: scope.enclosing_type.clone(),
                },
                stack,
            );
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope<'tree>,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let Some((code_unit, name, identity_name)) =
            csharp_type_code_unit(self.file, self.source, node, scope)
        else {
            return;
        };
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope
                .enclosing_type
                .as_ref()
                .map(|enclosing| enclosing.unit.clone()),
            None,
        );
        self.parsed.add_raw_supertypes(
            code_unit.clone(),
            extract_csharp_supertypes(node, self.source),
        );
        self.add_source_signature(
            node,
            code_unit.clone(),
            // Recorded, not merely present: canonical identity reads a type
            // declaration's arity, so a nongeneric type must be a proven zero
            // rather than an unread list (#1651).
            SignatureMetadata::new(csharp_type_signature(node, self.source), Vec::new())
                .with_recorded_type_parameters(csharp_declaration_type_parameters(
                    node,
                    self.source,
                ))
                .with_class_like_kind(match node.kind() {
                    "class_declaration" | "record_declaration" => ClassLikeKind::Class,
                    "interface_declaration" => ClassLikeKind::Interface,
                    "struct_declaration" | "record_struct_declaration" => ClassLikeKind::Struct,
                    "enum_declaration" => ClassLikeKind::Enum,
                    _ => unreachable!("admitted C# type declaration"),
                }),
        );
        self.visit_primary_constructor(node, scope, &code_unit, &name);

        if let Some(body) = cs_type_body(node) {
            let mut lexical_scope = scope.lexical_scope.clone();
            lexical_scope.push(identity_name);
            self.push_children(
                body,
                CSharpScope {
                    package_name: scope.package_name.clone(),
                    lexical_scope,
                    enclosing_type: Some(CSharpEnclosingType {
                        declaration: node,
                        unit: code_unit,
                        declared_name: name,
                    }),
                },
                stack,
            );
        }
    }

    /// Index one callable member of `scope`'s enclosing type, and report the
    /// unit it minted so a caller that adopted the declaration can grow the
    /// owner's range with it.
    fn visit_method(&mut self, node: Node<'_>, scope: &CSharpScope<'_>) -> Option<CodeUnit> {
        let enclosing = scope.enclosing_type.as_ref()?;
        let parent = &enclosing.unit;
        if self.current_is_test_method {
            self.parsed.mark_test_region(parent);
        }
        let name_node = node.child_by_field_name("name")?;
        let name = cs_ident_text(name_node, self.source);
        if name.is_empty() {
            return None;
        }
        let signature_key = csharp_method_signature_key(node, self.source);
        let fq = parent
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(name, SegmentKind::Member));
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(signature_key),
            false,
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_method_skeleton(node, self.source);
        self.add_source_signature(
            node,
            code_unit.clone(),
            csharp_signature_metadata(
                signature,
                node,
                self.source,
                &scope.lexical_scope,
                &self.ancestry,
                &self.current_properties,
            )
            .with_dispatch_extensibility(crate::syntax::csharp_type_member_dispatch_extensibility(
                self.source,
                node,
                csharp_has_modifier(self.source, node, "static"),
                Some(enclosing.declaration),
            ))
            .with_callable_modifiers(
                self.current_properties.is_static,
                false,
                csharp_declared_visibility(
                    node,
                    self.source,
                    crate::syntax::csharp_type_member_default_visibility(Some(
                        enclosing.declaration,
                    )),
                ),
            ),
        );
        Some(code_unit)
    }

    /// A primary constructor (`record Point(int X, int Y)`, and the C# 12
    /// `class Widget(int size)` / `struct Pair(int a, int b)` spelling of the
    /// same thing) declares a constructor with its own parameter arity, so it
    /// is indexed exactly like an explicit one (#1797).
    ///
    /// Without it a record's only constructor is invisible: `new Point(1, 2)`
    /// resolved to the *type*, and a record that also writes an explicit
    /// constructor resolved every creation to that one whatever its arity. The
    /// declaration node stays the type declaration -- it carries the parameter
    /// list, the modifiers and the type parameters the metadata is built from
    /// -- while the recorded range stops at the parameter list so the
    /// constructor never claims the type's body.
    fn visit_primary_constructor(
        &mut self,
        node: Node<'_>,
        scope: &CSharpScope<'_>,
        parent: &CodeUnit,
        declared_name: &str,
    ) {
        // Only a class, struct or record declaration can carry one; the grammar
        // gives no other visited type declaration a `parameter_list` child.
        let Some(parameters) = csharp_parameter_list_node(node) else {
            return;
        };
        let fq = parent
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(declared_name, SegmentKind::Member));
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{declared_name}", parent.short_name()),
            Some(csharp_parameter_key(node, self.source)),
            false,
            fq,
        );
        self.parsed.add_code_unit_with_range(
            code_unit.clone(),
            Range {
                start_byte: node.start_byte(),
                end_byte: parameters.end_byte(),
                start_line: node.start_position().row + 1,
                end_line: parameters.end_position().row + 1,
            },
            Some(parent.clone()),
            None,
        );
        let signature = format!(
            "{declared_name}{}",
            csharp_rendered_parameter_text(node, self.source)
        );
        self.add_source_signature(
            node,
            code_unit,
            csharp_signature_metadata(
                signature,
                node,
                self.source,
                &scope.lexical_scope,
                &self.ancestry,
                &self.current_properties,
            )
            // No constructor is dynamically dispatched, which
            // `csharp_callable_dispatch_extensibility` states for the
            // explicit spelling by its node kind. This one's node is the
            // type declaration, so an `abstract`/`virtual` modifier there
            // would otherwise be read as the constructor's own.
            .with_dispatch_extensibility(DispatchExtensibility::Closed),
        );
    }

    fn visit_constructor(&mut self, node: Node<'_>, scope: &CSharpScope<'_>) {
        let Some(enclosing) = &scope.enclosing_type else {
            return;
        };
        let parent = &enclosing.unit;
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_ident_text(name_node, self.source);
        // C# requires a constructor to be named after the type that declares it,
        // so a mismatch never occurs in source the compiler accepts. It is still
        // reachable through parse recovery: an `#if !DEBUG` region between a
        // `try` block and its `catch` chain makes tree-sitter re-parse trailing
        // catch clauses at class-body level as `constructor_declaration` nodes
        // named `catch` (issue #1800), which used to reach the index as real
        // `Function` members. Skip silently rather than assert -- this is a
        // misparse of otherwise valid source, not a broken internal invariant.
        if name != enclosing.declared_name {
            return;
        }
        let fq = parent
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(name, SegmentKind::Member));
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(csharp_parameter_key(node, self.source)),
            false,
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_constructor_skeleton(node, self.source);
        self.add_source_signature(
            node,
            code_unit,
            csharp_signature_metadata(
                signature,
                node,
                self.source,
                &scope.lexical_scope,
                &self.ancestry,
                &self.current_properties,
            )
            .with_callable_modifiers(
                self.current_properties.is_static,
                true,
                csharp_declared_visibility(
                    node,
                    self.source,
                    csharp_default_member_visibility(node, &self.ancestry),
                ),
            ),
        );
    }

    fn visit_property(&mut self, node: Node<'_>, scope: &CSharpScope<'_>) {
        let Some(enclosing) = &scope.enclosing_type else {
            return;
        };
        let parent = &enclosing.unit;
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_ident_text(name_node, self.source);
        if name.is_empty() {
            return;
        }
        let fq = parent
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_property_signature(node, self.source);
        self.add_source_signature(
            node,
            code_unit,
            csharp_dispatch_signature_metadata(
                signature,
                node,
                self.source,
                &self.ancestry,
                &self.current_properties,
            ),
        );
    }

    fn visit_field_declaration(&mut self, node: Node<'_>, scope: &CSharpScope<'_>) {
        let Some(enclosing) = &scope.enclosing_type else {
            return;
        };
        let parent = &enclosing.unit;
        let Some(declaration) = node
            .child_by_field_name("declaration")
            .or_else(|| first_named_child_of_kind(node, "variable_declaration"))
        else {
            return;
        };

        let prefix = csharp_field_prefix(node, self.source);
        let type_text = self
            .current_properties
            .display_type_text
            .clone()
            .unwrap_or_default();
        let return_type_identity = self.current_properties.return_type_identity.clone();

        let mut cursor = declaration.walk();
        for child in declaration.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let name = cs_ident_text(name_node, self.source);
            if name.is_empty() {
                continue;
            }
            let fq = parent
                .fq()
                .clone()
                .with_pushed(segment_interner().intern(name, SegmentKind::Member));
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
                fq,
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                child,
                self.source,
                Some(parent.clone()),
                None,
            );
            let signature = csharp_field_signature(&prefix, &type_text, child, self.source);
            self.add_source_signature(
                child,
                code_unit,
                SignatureMetadata::new(signature, Vec::new())
                    .with_return_type_text(self.current_properties.display_type_text.clone())
                    .with_return_type_identity(return_type_identity.clone())
                    .with_field_modifiers(
                        self.current_properties.is_static || self.current_properties.is_const,
                        self.current_properties.is_const || self.current_properties.is_readonly,
                    )
                    .with_field_initializer(
                        crate::syntax::variable_declarator_initializer(child).is_some(),
                    )
                    .with_source_declared_visibility(csharp_declared_visibility(
                        node,
                        self.source,
                        csharp_default_member_visibility(node, &self.ancestry),
                    ))
                    .with_dispatch_extensibility(DispatchExtensibility::Closed),
            );
        }
    }

    fn visit_enum_member(&mut self, node: Node<'_>, scope: &CSharpScope<'_>) {
        let Some(enclosing) = &scope.enclosing_type else {
            return;
        };
        let parent = &enclosing.unit;
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_ident_text(name_node, self.source);
        if name.is_empty() {
            return;
        }
        let fq = parent
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_render_node(node, self.source);
        self.add_source_signature(
            node,
            code_unit,
            SignatureMetadata::new(signature, Vec::new())
                .with_dispatch_extensibility(DispatchExtensibility::Closed),
        );
    }
}

fn csharp_namespace_path_from_declaration(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let name_node = node.child_by_field_name("name")?;
    csharp_namespace_path(name_node, source)
}

/// The member declaration a top-level `global_statement` holds when parser
/// recovery detached it from a type body, or `None` when the statement holds
/// no declaration this walk can place.
///
/// Only the statement's own `local_function_statement` qualifies. A local
/// function nested deeper inside a detached statement is a genuine local
/// function of the method the recovery lost, and a field, property or
/// constructor reaches the top level wearing a shape a genuine top-level
/// statement spells the same way -- `local_declaration_statement` for both a
/// field and a `var`, a bare `block` for a constructor body -- so those stay
/// unowned rather than guessed at.
fn csharp_recovered_type_member(node: Node<'_>) -> Option<Node<'_>> {
    debug_assert_eq!(
        node.kind(),
        "global_statement",
        "only a top-level statement can hold a detached member"
    );
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "local_function_statement")
}

fn csharp_type_code_unit(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    scope: &CSharpScope<'_>,
) -> Option<(CodeUnit, String, String)> {
    let name_node = node.child_by_field_name("name")?;
    let name = cs_ident_text(name_node, source);
    if name.is_empty() {
        return None;
    }
    let arity = node
        .child_by_field_name("type_parameters")
        .or_else(|| first_named_child_of_kind(node, "type_parameter_list"))
        .map_or(0, count_type_parameters);
    let identity_name = if arity == 0 {
        name.to_string()
    } else {
        format!("{name}`{arity}")
    };
    let short_name = if let Some(enclosing) = &scope.enclosing_type {
        format!("{}${identity_name}", enclosing.unit.short_name())
    } else {
        identity_name.clone()
    };
    let fq = match &scope.enclosing_type {
        Some(enclosing) => enclosing
            .unit
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(&identity_name, SegmentKind::Nested)),
        None => csharp_package_fq(&scope.package_name)
            .with_pushed(segment_interner().intern(&identity_name, SegmentKind::Type)),
    };
    Some((
        CodeUnit::new_fq(
            file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            fq,
        ),
        name.to_string(),
        identity_name,
    ))
}

pub(crate) fn count_type_parameters(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter")
        .count()
}

fn collect_csharp_type_identifier(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    if node.kind() == "attribute"
        && let Some(name) = node.child_by_field_name("name")
    {
        identifiers.extend(crate::syntax::csharp_attribute_type_names(name, source));
    }
    if let Some(root) = csharp_type_reference_root(node) {
        let text = csharp_type_node_identity(root, source);
        if !text.is_empty() {
            identifiers.insert(text);
        }
    }
    if let Some(candidate) = csharp_constant_pattern_type_candidate(node) {
        let text = csharp_type_node_identity(candidate, source);
        if !text.is_empty() {
            identifiers.insert(text);
        }
    }
    if let Some(receiver) = csharp_member_access_type_receiver(node) {
        let text = csharp_type_node_identity(receiver, source);
        if !text.is_empty() {
            identifiers.insert(text);
        }
    }
}

// Normalize trivia without changing the contents of literal tokens. The
// tree supplies literal extents, including verbatim/raw/interpolated strings.
fn csharp_render_range(node: Node<'_>, source: &str, range: std::ops::Range<usize>) -> String {
    let mut literals = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.end_byte() <= range.start || current.start_byte() >= range.end {
            continue;
        }
        if current.kind().ends_with("_literal")
            || current.kind() == "interpolated_string_expression"
        {
            literals.push(current.byte_range());
            continue;
        }
        for index in (0..current.named_child_count()).rev() {
            stack.push(current.named_child(index).expect("named child"));
        }
    }
    let mut result = String::new();
    let mut position = range.start;
    for literal in literals
        .into_iter()
        .chain(std::iter::once(range.end..range.end))
    {
        for ch in source[position..literal.start].chars() {
            if ch.is_whitespace() {
                if !result.ends_with(' ') {
                    result.push(' ');
                }
            } else {
                result.push(ch);
            }
        }
        result.push_str(&source[literal.clone()]);
        position = literal.end;
    }
    result
}

fn csharp_render_node(node: Node<'_>, source: &str) -> String {
    csharp_render_range(node, source, node.byte_range())
        .trim()
        .to_string()
}

fn cs_namespace_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| last_named_child(node))
}

fn cs_type_body(node: Node<'_>) -> Option<Node<'_>> {
    child_by_field_or_named_child_of_kinds(node, "body", &["declaration_list"])
}

fn csharp_type_signature(node: Node<'_>, source: &str) -> String {
    let end = cs_type_body(node).map_or(node.end_byte(), |body| body.start_byte());
    let head = csharp_render_range(node, source, node.start_byte()..end);
    format!("{} {{", head.trim())
}

fn extract_csharp_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(base_list) = first_named_child_of_kind(node, "base_list") else {
        return Vec::new();
    };
    let mut supertypes = Vec::new();
    let mut cursor = base_list.walk();
    for child in base_list.named_children(&mut cursor) {
        let text = csharp_type_node_identity(child, source);
        if !text.is_empty() {
            supertypes.push(text);
        }
    }
    supertypes
}

fn csharp_method_skeleton(node: Node<'_>, source: &str) -> String {
    let end = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .or_else(|| {
            (0..node.child_count())
                .rev()
                .filter_map(|index| node.child(index))
                .find(|child| child.kind() == ";")
                .map(|semicolon| semicolon.start_byte())
        })
        .unwrap_or(node.end_byte());
    let head = csharp_render_range(node, source, node.start_byte()..end);
    format!("{} {{ \u{2026} }}", head.trim())
}

fn csharp_method_signature_key(node: Node<'_>, source: &str) -> String {
    let parameters = csharp_parameter_key(node, source);
    let generic_arity = node
        .child_by_field_name("type_parameters")
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "type_parameter_list")
        })
        .map_or(0, |type_parameters| type_parameters.named_child_count());
    if generic_arity == 0 {
        parameters
    } else {
        format!("`{generic_arity}{parameters}")
    }
}

fn csharp_constructor_skeleton(node: Node<'_>, source: &str) -> String {
    csharp_method_skeleton(node, source)
}

fn csharp_dispatch_signature_metadata<'tree>(
    signature: String,
    node: Node<'tree>,
    source: &str,
    ancestry: &ParentIndex<'tree>,
    properties: &CSharpDeclarationProperties,
) -> SignatureMetadata {
    SignatureMetadata::new(signature, Vec::new())
        .with_return_type_text(properties.return_type_text.clone())
        .with_return_type_identity(properties.return_type_identity.clone())
        .with_field_modifiers(
            properties.is_static || properties.is_const,
            properties.is_const || properties.is_readonly,
        )
        .with_dispatch_extensibility(crate::syntax::csharp_callable_dispatch_extensibility(
            source,
            node,
            properties.is_static,
            ancestry,
        ))
}

/// The accessibility a C# declaration writes, or `default` when it writes
/// none. C# defaults differ by position -- a class member is private, a
/// top-level type is internal -- so the caller states the default for its own
/// position rather than this helper guessing one.
pub(crate) fn csharp_declared_visibility(
    node: Node<'_>,
    source: &str,
    default: DeclaredVisibility,
) -> DeclaredVisibility {
    for (modifier, visibility) in [
        ("public", DeclaredVisibility::Public),
        ("protected", DeclaredVisibility::Protected),
        ("internal", DeclaredVisibility::Internal),
        ("private", DeclaredVisibility::Private),
    ] {
        if csharp_has_modifier(source, node, modifier) {
            return visibility;
        }
    }
    default
}

/// Which member of the override-modifier family this declaration writes.
///
/// Read from the declaration's own `modifier` children through
/// [`csharp_has_modifier`], which walks tree-sitter nodes rather than scanning
/// text. C# forbids writing two of these together (`virtual override`,
/// `new override` and `abstract virtual` are all compile errors), so the first
/// one found is the only one there is.
///
/// A declaration that writes none of them returns `NotDeclared`, which is a
/// positive record: in C# a derived member that redefines a base member
/// without `override` *hides* it (implicit `new`, compiler warning CS0108).
/// Method families (#1721) need that distinct from "nobody read the
/// modifiers", which is the absent field rather than this value.
fn csharp_override_modifier(source: &str, node: Node<'_>) -> CallableOverrideModifier {
    for (modifier, recorded) in [
        ("override", CallableOverrideModifier::Override),
        ("virtual", CallableOverrideModifier::Virtual),
        ("abstract", CallableOverrideModifier::Abstract),
        ("new", CallableOverrideModifier::Hiding),
    ] {
        if csharp_has_modifier(source, node, modifier) {
            return recorded;
        }
    }
    CallableOverrideModifier::NotDeclared
}

fn csharp_signature_metadata<'tree>(
    signature: String,
    node: Node<'tree>,
    source: &str,
    lexical_scope: &[String],
    ancestry: &ParentIndex<'tree>,
    properties: &CSharpDeclarationProperties,
) -> SignatureMetadata {
    let callable_arity = csharp_callable_arity(node, source);
    let type_parameters = csharp_method_type_parameters(node, source);
    let return_type_text = properties.return_type_text.clone();
    let return_type_identity = properties.return_type_identity.clone();
    let bare_return_type_parameter =
        csharp_bare_return_type_parameter(node, source, &type_parameters);
    let extension_receiver_type_node = csharp_extension_receiver_type_node(node, source);
    let extension_receiver_type = extension_receiver_type_node
        .map(|type_node| csharp_type_node_identity(type_node, source))
        .filter(|receiver_type| !receiver_type.is_empty());
    let extension_receiver_type_identity = extension_receiver_type_node
        .and_then(|type_node| csharp_structured_type_identity(type_node, source, lexical_scope));
    let extension_receiver_is_unconstrained_type_parameter = extension_receiver_type_node
        .is_some_and(|type_node| {
            let receiver = cs_node_text(type_node, source).trim();
            type_node.kind() == "identifier"
                && type_parameters
                    .iter()
                    .any(|parameter| parameter == receiver)
                && !csharp_method_type_parameter_has_constraints(node, source, receiver)
        });
    let parameter_types = csharp_callable_parameter_types(node, source);
    let parameters = csharp_parameter_list_node(node).map_or_else(Vec::new, |parameter_list| {
        // Primary constructors render as Name(parameters); ordinary callables
        // retain the normalized source header, including attributes/modifiers.
        let parameters_start = if matches!(
            node.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) {
            cs_ident_text(node.child_by_field_name("name").expect("type name"), source).len()
        } else {
            csharp_render_range(node, source, node.start_byte()..parameter_list.start_byte())
                .trim_start()
                .len()
        };
        csharp_parameter_label_nodes(node)
            .into_iter()
            .map(|name| {
                let label = cs_node_text(name, source);
                let start = parameters_start
                    + csharp_render_range(
                        parameter_list,
                        source,
                        parameter_list.start_byte()..name.start_byte(),
                    )
                    .len();
                let end = start + label.len();
                debug_assert_eq!(&signature[start..end], label);
                ParameterMetadata::new(label, start, end).with_name(cs_ident_text(name, source))
            })
            .collect()
    });
    let metadata = SignatureMetadata::new(signature, parameters)
        .with_callable_arity(callable_arity)
        .with_callable_parameter_types(parameter_types)
        .with_type_parameters(type_parameters)
        .with_return_type_text(return_type_text)
        .with_return_type_identity(return_type_identity)
        .with_bare_return_type_parameter(bare_return_type_parameter)
        .with_extension_receiver_type(extension_receiver_type)
        .with_extension_receiver_type_identity(extension_receiver_type_identity)
        .with_extension_receiver_is_unconstrained_type_parameter(
            extension_receiver_is_unconstrained_type_parameter,
        );
    metadata
        .with_callable_override_modifier(csharp_override_modifier(source, node))
        .with_dispatch_extensibility(crate::syntax::csharp_callable_dispatch_extensibility(
            source,
            node,
            properties.is_static,
            ancestry,
        ))
}

fn csharp_extension_receiver_type_node<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let parameters = csharp_parameter_list_node(node)?;
    let mut parameters_cursor = parameters.walk();
    let first_parameter = parameters
        .named_children(&mut parameters_cursor)
        .find(|child| child.kind() == "parameter")?;
    let mut parameter_cursor = first_parameter.walk();
    let has_this_modifier = first_parameter
        .named_children(&mut parameter_cursor)
        .any(|child| child.kind() == "modifier" && cs_node_text(child, source) == "this");
    if !has_this_modifier {
        return None;
    }
    first_parameter.child_by_field_name("type")
}

/// The type a declaration states for the value it declares: a method's or a
/// property's return type, a field's or a parameter's type.
pub(crate) fn csharp_declared_type_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("returns")
        .or_else(|| node.child_by_field_name("return_type"))
        .or_else(|| node.child_by_field_name("type"))
}

fn csharp_bare_return_type_parameter(
    node: Node<'_>,
    source: &str,
    type_parameters: &[String],
) -> Option<String> {
    let return_type = node
        .child_by_field_name("returns")
        .or_else(|| node.child_by_field_name("return_type"))?;
    if return_type.kind() != "identifier" {
        return None;
    }
    let return_type = source
        .get(return_type.start_byte()..return_type.end_byte())
        .map(str::trim)
        .filter(|return_type| !return_type.is_empty())?;
    type_parameters
        .iter()
        .any(|parameter| parameter == return_type)
        .then(|| return_type.to_string())
}

fn csharp_method_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(type_parameters) = node.child_by_field_name("type_parameters").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "type_parameter_list")
    }) else {
        return Vec::new();
    };
    let mut cursor = type_parameters.walk();
    type_parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| {
            let name = parameter
                .child_by_field_name("name")
                .or_else(|| parameter.named_child(0))
                .unwrap_or(parameter);
            let text = cs_ident_text(name, source);
            (!text.is_empty()).then(|| text.to_string())
        })
        .collect()
}

fn csharp_method_type_parameter_has_constraints(
    node: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter_constraints_clause")
        .any(|clause| {
            let mut clause_cursor = clause.walk();
            clause.named_children(&mut clause_cursor).any(|child| {
                child.kind() == "identifier" && cs_ident_text(child, source) == parameter_name
            })
        })
}

fn csharp_declaration_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    csharp_method_type_parameters(node, source)
}

enum CSharpStructuredTypeFrame<'tree> {
    Visit(Node<'tree>),
    WrapReference,
    WrapPointer,
    WrapArray,
    BuildGeneric { argument_count: usize },
}

/// Persist the parser-proven shape of a C# declared type. The arena builder and
/// explicit frame stack keep indexing safe even for adversarially deep type
/// syntax, while the lexical scope preserves the exact nested lookup context
/// needed by bounded consumers.
fn csharp_structured_type_identity(
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeIdentity> {
    let mut frames = vec![CSharpStructuredTypeFrame::Visit(node)];
    let mut values = Vec::new();
    let mut builder = StructuredTypeIdentityBuilder::default();

    while let Some(frame) = frames.pop() {
        match frame {
            CSharpStructuredTypeFrame::Visit(node) => match node.kind() {
                "type" | "simple_base_type" | "primary_constructor_base_type" => {
                    frames.push(CSharpStructuredTypeFrame::Visit(
                        child_by_field_or_first_named_child(node, "type")?,
                    ));
                }
                // Nullable reference types retain the same nominal declaration.
                // Value-type nullable members are library-supplied and therefore
                // do not publish a workspace member target through this path.
                "nullable_type" => {
                    frames.push(CSharpStructuredTypeFrame::Visit(
                        child_by_field_or_first_named_child(node, "type")?,
                    ));
                }
                "ref_type" => {
                    frames.push(CSharpStructuredTypeFrame::WrapReference);
                    frames.push(CSharpStructuredTypeFrame::Visit(
                        child_by_field_or_first_named_child(node, "type")?,
                    ));
                }
                "pointer_type" => {
                    frames.push(CSharpStructuredTypeFrame::WrapPointer);
                    frames.push(CSharpStructuredTypeFrame::Visit(
                        child_by_field_or_first_named_child(node, "type")?,
                    ));
                }
                "array_type" => {
                    frames.push(CSharpStructuredTypeFrame::WrapArray);
                    frames.push(CSharpStructuredTypeFrame::Visit(
                        child_by_field_or_first_named_child(node, "type")?,
                    ));
                }
                "identifier"
                | "predefined_type"
                | "qualified_name"
                | "alias_qualified_name"
                | "generic_name" => {
                    let (name, arguments) =
                        csharp_structured_named_type(node, source, lexical_scope)?;
                    values.push(builder.named(name)?);
                    if !arguments.is_empty() {
                        frames.push(CSharpStructuredTypeFrame::BuildGeneric {
                            argument_count: arguments.len(),
                        });
                        frames.extend(
                            arguments
                                .into_iter()
                                .rev()
                                .map(CSharpStructuredTypeFrame::Visit),
                        );
                    }
                }
                _ => return None,
            },
            CSharpStructuredTypeFrame::WrapReference => {
                let inner = values.pop()?;
                values.push(builder.reference(inner)?);
            }
            CSharpStructuredTypeFrame::WrapPointer => {
                let inner = values.pop()?;
                values.push(builder.pointer(inner)?);
            }
            CSharpStructuredTypeFrame::WrapArray => {
                let inner = values.pop()?;
                values.push(builder.array(inner)?);
            }
            CSharpStructuredTypeFrame::BuildGeneric { argument_count } => {
                let value_count = argument_count.checked_add(1)?;
                let start = values.len().checked_sub(value_count)?;
                let mut built = values.split_off(start);
                let base = built.remove(0);
                values.push(builder.generic(base, built)?);
            }
        }
    }

    (values.len() == 1)
        .then(|| values.pop())
        .flatten()
        .and_then(|root| builder.finish(root))
}

fn csharp_structured_named_type<'tree>(
    node: Node<'tree>,
    source: &str,
    lexical_scope: &[String],
) -> Option<(StructuredTypeName, Vec<Node<'tree>>)> {
    let mut path = Vec::new();
    let mut arguments = Vec::new();
    let mut absolute = false;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "predefined_type" => {
                path.push(csharp_identifier_text(current, source)?);
            }
            "generic_name" => {
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(0))?;
                let type_arguments = current
                    .child_by_field_name("type_arguments")
                    .or_else(|| first_named_child_of_kind(current, "type_argument_list"))?;
                let mut cursor = type_arguments.walk();
                let generic_arguments = type_arguments
                    .named_children(&mut cursor)
                    .collect::<Vec<_>>();
                let name = csharp_identifier_text(name, source)?;
                path.push(format!("{name}`{}", generic_arguments.len()));
                arguments.extend(generic_arguments);
            }
            "qualified_name" => {
                let qualifier = current
                    .child_by_field_name("qualifier")
                    .or_else(|| current.named_child(0))?;
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
                stack.push(name);
                stack.push(qualifier);
            }
            "alias_qualified_name" => {
                let alias = current
                    .child_by_field_name("alias")
                    .or_else(|| current.named_child(0))?;
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
                let alias = csharp_identifier_text(alias, source)?;
                if alias == "global" {
                    absolute = true;
                } else {
                    path.push(alias);
                }
                stack.push(name);
            }
            _ => return None,
        }
    }
    let name = StructuredTypeName::new(path, lexical_scope.to_vec(), absolute)?;
    Some((name, arguments))
}

fn csharp_identifier_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = cs_ident_text(node, source);
    (!text.is_empty()).then(|| text.to_string())
}

fn csharp_namespace_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut path = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" => path.push(csharp_identifier_text(current, source)?),
            "qualified_name" => {
                let qualifier = current
                    .child_by_field_name("qualifier")
                    .or_else(|| current.named_child(0))?;
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
                stack.push(name);
                stack.push(qualifier);
            }
            _ => return None,
        }
    }
    (!path.is_empty()).then_some(path)
}

fn csharp_join_namespace(prefix: &str, path: &[String]) -> String {
    if prefix.is_empty() {
        path.join(".")
    } else if path.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}.{}", path.join("."))
    }
}

fn csharp_callable_arity(node: Node<'_>, source: &str) -> CallableArity {
    let Some(parameters) = csharp_parameter_list_node(node) else {
        return CallableArity::exact(0);
    };
    let mut required = 0usize;
    let mut total = 0usize;
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if parameter.kind() != "parameter" {
            continue;
        }
        total += 1;
        let mut parameter_cursor = parameter.walk();
        let optional = parameter
            .children(&mut parameter_cursor)
            .any(|child| child.kind() == "=")
            || csharp_parameter_has_optional_attribute(parameter, source);
        if !optional {
            required += 1;
        }
    }
    let repeated = csharp_parameter_list_has_params(parameters);
    if repeated {
        total += 1;
    }
    CallableArity::new(required, total, repeated)
}

fn csharp_parameter_has_optional_attribute(parameter: Node<'_>, source: &str) -> bool {
    let mut stack = vec![parameter];
    while let Some(node) = stack.pop() {
        if node.kind() == "attribute"
            && let Some(name) = node.child_by_field_name("name")
            && csharp_attribute_type_names(name, source)
                .into_iter()
                .any(|candidate| {
                    let candidate = candidate.strip_prefix("global::").unwrap_or(&candidate);
                    matches!(
                        candidate,
                        "Optional"
                            | "OptionalAttribute"
                            | "System.Runtime.InteropServices.Optional"
                            | "System.Runtime.InteropServices.OptionalAttribute"
                    )
                })
        {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

fn csharp_parameter_list_has_params(parameters: Node<'_>) -> bool {
    let mut cursor = parameters.walk();
    parameters
        .children(&mut cursor)
        .any(|child| child.kind() == "params")
}

/// The parameter list a callable declaration declares.
///
/// A method, constructor or delegate carries it as the `parameters` field. A
/// primary constructor is written on its type declaration, where the grammar
/// admits the list as a plain named child (`repeat(choice($.type_parameter_list,
/// $.parameter_list))`) with no field name, so the field lookup alone cannot see
/// it (#1797).
fn csharp_parameter_list_node<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    node.child_by_field_name("parameters")
        .or_else(|| first_named_child_of_kind(node, "parameter_list"))
}

fn csharp_rendered_parameter_text(node: Node<'_>, source: &str) -> String {
    csharp_parameter_list_node(node)
        .map(|parameters| csharp_render_node(parameters, source))
        .unwrap_or_else(|| "()".to_string())
}

/// The written type of each parameter of a callable, in declaration order.
///
/// Read from the parameter `type` nodes, so the spelling is the declaration's
/// own and no caller has to recover it from the rendered signature label. The
/// trailing `params` parameter is not a `parameter` node -- the grammar
/// flattens it into the parameter list's own `type` and `name` fields -- so it
/// is appended the same way [`csharp_parameter_label_nodes`] appends its label,
/// and the two lists stay index-aligned.
///
/// A parameter with no `type` field contributes an empty spelling rather than
/// disappearing, because dropping it would shift every later parameter's index.
fn csharp_callable_parameter_types(node: Node<'_>, source: &str) -> Vec<String> {
    csharp_callable_parameter_type_nodes(node)
        .into_iter()
        .map(|type_node| {
            type_node
                .map(|type_node| csharp_type_node_identity(type_node, source))
                .unwrap_or_default()
        })
        .collect()
}

/// The `type` node of each parameter of a callable, in the order
/// [`csharp_callable_parameter_types`] records their spellings.
///
/// A query that needs the scope a parameter's type is written in reads the
/// node back from the declaring file's tree with this function, so the index
/// it is given is the persisted parameter index by construction.
pub fn csharp_callable_parameter_type_nodes(node: Node<'_>) -> Vec<Option<Node<'_>>> {
    let Some(parameters) = csharp_parameter_list_node(node) else {
        return Vec::new();
    };
    let mut types = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        types.push(child.child_by_field_name("type"));
    }
    if csharp_parameter_list_has_params(parameters) {
        types.push(parameters.child_by_field_name("type"));
    }
    types
}

fn csharp_parameter_label_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = csharp_parameter_list_node(node) else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        if let Some(name) = child.child_by_field_name("name") {
            labels.push(name);
            continue;
        }
        let mut param_cursor = child.walk();
        if let Some(name) = child
            .named_children(&mut param_cursor)
            .find(|candidate| candidate.kind() == "identifier")
        {
            labels.push(name);
        }
    }
    if csharp_parameter_list_has_params(parameters)
        && let Some(name) = parameters.child_by_field_name("name")
    {
        labels.push(name);
    }
    labels
}

fn csharp_property_signature(node: Node<'_>, source: &str) -> String {
    csharp_render_node(node, source)
}

fn csharp_parameter_key(node: Node<'_>, source: &str) -> String {
    let Some(parameters) = csharp_parameter_list_node(node) else {
        return "()".to_string();
    };
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let part = child
            .child_by_field_name("type")
            .map(|type_node| csharp_render_node(type_node, source))
            .unwrap_or_else(|| csharp_render_node(child, source));
        parts.push(part);
    }
    if csharp_parameter_list_has_params(parameters)
        && let Some(type_node) = parameters.child_by_field_name("type")
    {
        parts.push(csharp_render_node(type_node, source));
    }
    format!("({})", parts.join(", "))
}

fn csharp_field_prefix(field_node: Node<'_>, source: &str) -> String {
    let mut cursor = field_node.walk();
    field_node
        .named_children(&mut cursor)
        .filter(|node| node.kind() == "modifier")
        .map(|node| cs_node_text(node, source))
        .collect::<Vec<_>>()
        .join(" ")
}

fn csharp_field_signature(
    prefix: &str,
    type_text: &str,
    declarator: Node<'_>,
    source: &str,
) -> String {
    let name = declarator
        .child_by_field_name("name")
        .map(|child| cs_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let initializer = declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .or_else(|| {
            let name = declarator.child_by_field_name("name");
            let mut cursor = declarator.walk();
            declarator
                .named_children(&mut cursor)
                .find(|child| Some(*child) != name && child.kind() != "bracketed_argument_list")
        })
        .and_then(|value| csharp_literal_initializer(value, source));

    let base = if prefix.is_empty() {
        format!("{type_text} {name}")
    } else {
        format!("{prefix} {type_text} {name}")
    };
    if let Some(initializer) = initializer {
        format!("{base} = {initializer};")
    } else {
        format!("{base};")
    }
}

fn csharp_literal_initializer(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "prefix_unary_expression" {
        let value = last_named_child(node)?;
        let has_sign = (0..node.child_count())
            .filter_map(|index| node.child(index))
            .any(|child| !child.is_named() && matches!(child.kind(), "+" | "-"));
        return (has_sign && matches!(value.kind(), "integer_literal" | "real_literal"))
            .then(|| csharp_render_node(node, source));
    }
    if matches!(
        node.kind(),
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "verbatim_string_literal"
            | "raw_string_literal"
            | "character_literal"
            | "boolean_literal"
            | "null_literal"
    ) {
        return Some(csharp_render_node(node, source));
    }
    None
}

use brokk_bifrost_core::analyzer::tree_walk::last_named_child;

#[cfg(test)]
mod primary_source_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
    use brokk_bifrost_test_macros::hardwon;

    fn parse(source: &str) -> ParsedFile {
        let tree = crate::preprocessor::parse_csharp(source).expect("C# primary tree");
        let file = ProjectFile::new(std::env::temp_dir(), "Primary.cs");
        parse_csharp_file(&file, source, &tree)
    }

    #[test]
    #[hardwon(
        "62b03791910c: a comment between global and using was selected as the namespace target"
    )]
    fn primary_using_imports_ignore_comment_extras() {
        use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;

        for (source, kind, alias, is_global) in [
            (
                "global /* before using */ using /* before target */ Shared.Tools;",
                StructuredImportPathKind::Namespace,
                None,
                true,
            ),
            (
                "global /* before using */ using static /* before target */ Shared.Tools;",
                StructuredImportPathKind::StaticMember,
                None,
                true,
            ),
            (
                "global using /* before alias */ Alias /* before equals */ = /* before target */ Shared.Tools;",
                StructuredImportPathKind::ImportFrom,
                Some("Alias"),
                true,
            ),
            (
                "using /* before target */ Shared.Tools;",
                StructuredImportPathKind::Namespace,
                None,
                false,
            ),
        ] {
            let parsed = parse(source);
            assert_eq!(parsed.imports.len(), 1, "{source}");
            let import = &parsed.imports[0];
            assert_eq!(import.raw_snippet, source);
            assert_eq!(import.is_global, is_global, "{source}");
            assert_eq!(import.alias.as_deref(), alias, "{source}");
            let path = import.path.as_ref().expect("structured import path");
            assert_eq!(path.kind, Some(kind), "{source}");
            assert_eq!(path.segments, ["Shared", "Tools"], "{source}");
            let facts = parsed.source_facts.as_ref().expect("canonical C# facts");
            assert_eq!(facts.imports.len(), 1, "{source}");
            assert_eq!(facts.imports[0].import_info(&facts.occurrences), *import);
        }
    }

    #[test]
    fn primary_declaration_and_structural_projections_share_occurrences() {
        let source = "using Alias = System.Text; namespace Demo; class Box(int size) { int x, y; void Run() { void Local() { Work(); } Local(); } }";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("canonical C# facts");
        assert_eq!(facts.source_bytes, source.len());
        assert!(parsed.declarations().iter().all(|unit| {
            parsed
                .source_declaration_units
                .iter()
                .any(|(_, linked)| linked == unit)
        }));
        assert_eq!(
            parsed.source_declaration_metadata.len(),
            parsed.source_declaration_units.len()
        );
        for link in &parsed.source_declaration_metadata {
            assert!(
                parsed.signature_metadata[&link.unit]
                    .get(link.metadata_ordinal)
                    .is_some()
            );
        }
        let class = parsed
            .source_declaration_metadata
            .iter()
            .find(|link| link.unit.short_name() == "Box")
            .expect("class metadata link");
        let constructor = parsed
            .source_declaration_metadata
            .iter()
            .find(|link| link.unit.short_name() == "Box.Box")
            .expect("primary constructor metadata link");
        assert_eq!(class.declaration, constructor.declaration);
        assert_ne!(class.unit, constructor.unit);
        let class_metadata = &parsed.signature_metadata[&class.unit][class.metadata_ordinal];
        let constructor_metadata =
            &parsed.signature_metadata[&constructor.unit][constructor.metadata_ordinal];
        assert_eq!(class_metadata.class_like_kind(), Some(ClassLikeKind::Class));
        assert_eq!(constructor_metadata.class_like_kind(), None);
        assert!(class_metadata.parameters().is_empty());
        assert_eq!(constructor_metadata.parameters()[0].name(), Some("size"));
        let run = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.short_name() == "Box.Run")
            .expect("method source link");
        let declaration = facts.occurrences.declaration(run.0);
        assert!(
            facts
                .structural
                .nodes()
                .iter()
                .any(|node| node.kind == NormalizedKind::Method
                    && node.occurrence == declaration.occurrence)
        );
        assert!(
            facts
                .structural
                .nodes()
                .iter()
                .any(|node| node.kind == NormalizedKind::Function)
        );
        assert_eq!(
            facts
                .structural
                .nodes()
                .iter()
                .filter(|node| node.kind == NormalizedKind::Call)
                .count(),
            2
        );
        assert!(
            !parsed
                .declarations()
                .iter()
                .any(|unit| unit.identifier() == "Local"),
            "body structural extraction must not broaden declaration admission"
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.package_name() == "Demo")
        );
        assert_eq!(facts.imports.len(), 1);
        assert_eq!(
            facts.imports[0].import_info(&facts.occurrences),
            parsed.imports[0]
        );
        let alias = facts.imports[0].alias_occurrence.expect("alias occurrence");
        let range = facts.occurrences.occurrence(alias).range;
        assert_eq!(&source[range.start_byte..range.end_byte], "Alias");
    }
    #[test]
    fn field_literals_and_modifiers_come_from_declarator_nodes() {
        let parsed = parse(
            r#"class C {
            [System.Obsolete("x = 99;")] public const int x = -2, y = +3;
            string text = "x = 10;";
            int computed = Make();
        }"#,
        );
        for (name, expected) in [
            ("x", "public const int x = -2;"),
            ("y", "public const int y = +3;"),
            ("text", "string text = \"x = 10;\";"),
            ("computed", "int computed;"),
        ] {
            let unit = parsed
                .declarations()
                .iter()
                .find(|unit| unit.identifier() == name)
                .expect("field declaration");
            assert_eq!(parsed.signatures[unit], [expected]);
        }
    }
    #[test]
    fn semantic_source_only_events_share_primary_properties_without_display_units() {
        let source = "namespace N { class C { static int[] Make() { return null; } string Read() => \"value\"; const int Value = 1; event System.Action Changed; } }";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().unwrap();
        let projections = parsed
            .csharp_semantic_declarations
            .iter()
            .map(|declaration| {
                let name = facts
                    .occurrences
                    .declaration(declaration.declaration)
                    .name
                    .unwrap();
                let range = facts.occurrences.occurrence(name).range;
                (&source[range.start_byte..range.end_byte], declaration)
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(projections["Make"].type_spelling.as_deref(), Some("int[]"));
        assert_eq!(
            projections["Make"].kind,
            CSharpSemanticDeclarationKind::StaticMethodReturn
        );
        assert_eq!(
            projections["Read"].kind,
            CSharpSemanticDeclarationKind::InstanceMethodReturn
        );
        assert_eq!(projections["Value"].type_spelling.as_deref(), Some("int"));
        assert!(projections["Value"].is_static);
        assert_eq!(
            projections["Changed"].type_spelling.as_deref(),
            Some("System.Action")
        );
        assert_eq!(projections["Changed"].namespace, ["N"]);
        assert!(
            !parsed
                .declarations()
                .iter()
                .any(|unit| unit.identifier() == "Changed")
        );
    }
}

#[cfg(test)]
mod grammar_regression_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Parser;

    #[test]
    #[hardwon(
        "#3197: The published C# grammar regression dropped local functions from the parse tree"
    )]
    fn static_local_function_preserves_declaration_and_following_call() {
        let source = "class Example { void Run() { static void Local(int value) {} Local(1); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar");
        let tree = parser.parse(source, None).expect("C# tree");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let class = tree.root_node().named_child(0).expect("class");
        let members = class.child_by_field_name("body").expect("class body");
        let method = members.named_child(0).expect("method");
        let body = method.child_by_field_name("body").expect("method body");
        assert_eq!(body.named_child_count(), 2);
        let local = body.named_child(0).expect("local function");
        assert_eq!(local.kind(), "local_function_statement");
        let name = local.child_by_field_name("name").expect("declaration name");
        assert_eq!(name.utf8_text(source.as_bytes()).unwrap(), "Local");
        let statement = body.named_child(1).expect("following statement");
        let call = statement.named_child(0).expect("following call");
        assert_eq!(call.kind(), "invocation_expression");
        let function = call.child_by_field_name("function").expect("call target");
        assert_eq!(function.utf8_text(source.as_bytes()).unwrap(), "Local");
    }

    /// C# permits `async` as an identifier outside modifier positions. A parser
    /// recovery at the invocation used to swallow the following member (#3073).
    #[test]
    #[hardwon(
        "#3073: The async identifier was misparsed as an expression and caused later declarations to disappear"
    )]
    fn contextual_async_argument_preserves_following_members() {
        let source = r#"readonly struct ArrayConverterCore {
    int F(params object[] xs) => 0;
    int Write(bool async, int ct) {
        F(async, ct).ToString();
        return 0;
    }
    int After() => 1;
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar");
        let tree = parser.parse(source, None).expect("C# tree");
        assert!(
            !tree.root_node().has_error(),
            "published Brokk grammar must parse without recovery:\n{}",
            tree.root_node().to_sexp()
        );

        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "ArrayConverterCore.cs",
        );
        let parsed = parse_csharp_file(&file, source, &tree);
        let mut declarations = parsed
            .declarations()
            .iter()
            .map(|unit| unit.short_name().to_string())
            .collect::<Vec<_>>();
        declarations.sort();
        assert_eq!(
            declarations,
            [
                "ArrayConverterCore",
                "ArrayConverterCore.After",
                "ArrayConverterCore.F",
                "ArrayConverterCore.Write",
            ]
        );
    }

    #[test]
    fn contextual_partial_and_required_assignments_preserve_following_members() {
        let source = r#"class Example {
    void Run() {
        var partial = Get();
        partial = partial.Clone();
        partial.Value = required.Value;
        var required = Get();
        required = required.Clone();
    }
    void After() { }
}
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar");
        let tree = parser.parse(source, None).expect("C# tree");
        assert!(
            !tree.root_node().has_error(),
            "published Brokk grammar must parse without recovery:\n{}",
            tree.root_node().to_sexp()
        );

        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "Example.cs",
        );
        let parsed = parse_csharp_file(&file, source, &tree);
        let mut declarations = parsed
            .declarations()
            .iter()
            .map(|unit| unit.short_name().to_string())
            .collect::<Vec<_>>();
        declarations.sort();
        assert_eq!(declarations, ["Example", "Example.After", "Example.Run"]);
    }
}

#[cfg(test)]
mod recovered_dispatch_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("a75f29823115: recovered virtual members lost open dispatch metadata")]
    fn recovered_virtual_member_retains_open_dispatch() {
        let source = "class Box { void Broken() { var required = Make(); required = required.Clone(); } public virtual void Recovered() {} }";
        let tree = crate::preprocessor::parse_csharp(source).unwrap();
        let file = ProjectFile::new(std::env::current_dir().unwrap(), "Box.cs");
        let parsed = parse_csharp_file(&file, source, &tree);
        let method = parsed
            .declarations()
            .iter()
            .find(|unit| unit.identifier() == "Recovered")
            .expect("the recovered method must be published");
        assert_eq!(method.short_name(), "Box.Recovered");
        let metadata = &parsed.signature_metadata[method];
        assert!(
            metadata
                .iter()
                .all(|row| row.dispatch_extensibility() == Some(DispatchExtensibility::Open)),
            "a recovered virtual member remains open: {metadata:?}"
        );
    }
}

#[cfg(test)]
mod signature_rendering_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: parameter labels selected type and default substrings"
    )]
    fn parameter_labels_follow_name_tokens() {
        let source = r#"class C { void M(int i, string s = "i", string @name = "s") {} }"#;
        let tree = crate::preprocessor::parse_csharp(source).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "Labels.cs");
        let parsed = parse_csharp_file(&file, source, &tree);
        let method = parsed
            .declarations()
            .iter()
            .find(|unit| unit.identifier() == "M")
            .unwrap();
        let metadata = &parsed.signature_metadata[method][0];
        let labels: Vec<_> = metadata
            .parameters()
            .iter()
            .map(|parameter| {
                (
                    parameter.label(),
                    parameter.start_byte(),
                    parameter.end_byte(),
                    parameter.name(),
                )
            })
            .collect();
        assert_eq!(
            labels,
            [
                ("i", 11, 12, Some("i")),
                ("s", 21, 22, Some("s")),
                ("@name", 37, 42, Some("name"))
            ]
        );
    }

    #[test]
    #[hardwon(
        "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: signatures split literal braces and collapsed literal whitespace"
    )]
    fn signatures_preserve_literal_values_and_structural_bodies() {
        let source = r#"[A("{")] class C { string Value = "a  b"; object Empty = null; [A("{")] void M(string value = "{  }") {} char Tab = '	'; string Verbatim = @"a  b"; string Raw = """a  b"""; string Expr() => "{"; }"#;
        let tree = crate::preprocessor::parse_csharp(source).unwrap();
        let class = tree.root_node().named_child(0).unwrap();
        let method = cs_type_body(class).unwrap().named_child(2).unwrap();
        assert_eq!(
            csharp_type_signature(class, source),
            r#"[A("{")] class C {"#
        );
        assert_eq!(
            csharp_method_skeleton(method, source),
            "[A(\"{\")] void M(string value = \"{  }\") { \u{2026} }"
        );
        let file = ProjectFile::new(std::env::temp_dir(), "Literals.cs");
        let parsed = parse_csharp_file(&file, source, &tree);
        let labels: Vec<_> = parsed
            .signature_metadata
            .values()
            .flatten()
            .map(SignatureMetadata::label)
            .collect();
        assert!(labels.contains(&r#"string Value = "a  b";"#), "{labels:?}");
        assert!(labels.contains(&"object Empty = null;"), "{labels:?}");
        assert!(labels.contains(&"char Tab = '\t';"), "{labels:?}");
        assert!(
            labels.contains(&r#"string Verbatim = @"a  b";"#),
            "{labels:?}"
        );
        assert!(
            labels.contains(&r#"string Raw = """a  b""";"#),
            "{labels:?}"
        );
        assert!(labels.contains(&"string Expr() { \u{2026} }"), "{labels:?}");
    }
}

#[cfg(test)]
mod declaration_boundary_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::model::StructuredTypeNodeView;

    #[test]
    fn declaration_names_modifiers_ranges_and_type_shapes_follow_grammar() {
        let source = "namespace Outer { namespace Inner { class C(int count) { public static int Value { get; } public int Instance { get; } int Number() => 0; string[] Text() => null; Box<int> Items() => null; global::N.Item Global() => null; } } }";
        let tree = crate::preprocessor::parse_csharp(source).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let file = ProjectFile::new(std::env::temp_dir(), "Shapes.cs");
        let parsed = parse_csharp_file(&file, source, &tree);
        let facts = parsed.source_facts.as_ref().unwrap();
        for link in &parsed.source_declaration_metadata {
            let declaration = facts.occurrences.declaration(link.declaration);
            let name = facts.occurrences.occurrence(
                declaration
                    .name
                    .expect("display declaration must link to its grammar name"),
            );
            let occurrence = facts.occurrences.occurrence(declaration.occurrence);
            let syntax_node = tree
                .root_node()
                .descendant_for_byte_range(occurrence.range.start_byte, occurrence.range.end_byte)
                .unwrap();
            let grammar_name = syntax_node
                .child_by_field_name("name")
                .expect("declaration name field");
            assert_eq!(name.range.start_byte, grammar_name.start_byte());
            assert_eq!(name.range.end_byte, grammar_name.end_byte());
            let metadata = &parsed.signature_metadata[&link.unit][link.metadata_ordinal];
            match link.unit.identifier() {
                "Value" => assert!(metadata.field_is_static()),
                "Instance" => assert!(!metadata.field_is_static()),
                "Number" | "Text" | "Items" | "Global" => {
                    let identity = metadata
                        .return_type_identity()
                        .expect("structured return type");
                    if link.unit.identifier() == "Text" {
                        assert!(identity.is_array());
                    } else {
                        let name = identity.nominal_name().unwrap();
                        assert_eq!(name.lexical_scope(), ["Outer", "Inner", "C"]);
                        match link.unit.identifier() {
                            "Number" => assert_eq!(name.path(), ["int"]),
                            "Global" => {
                                assert_eq!(name.path(), ["N", "Item"]);
                                assert!(name.is_absolute());
                            }
                            "Items" => {
                                assert_eq!(name.path(), ["Box`1"]);
                                let StructuredTypeNodeView::Generic { arguments, .. } =
                                    identity.view(identity.root_id()).unwrap()
                                else {
                                    panic!("generic shape");
                                };
                                let StructuredTypeNodeView::Named(argument) =
                                    identity.view(arguments[0]).unwrap()
                                else {
                                    panic!("nominal argument");
                                };
                                assert_eq!(argument.path(), ["int"]);
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                "C" if link.unit.is_function() => {
                    let parameter_list = csharp_parameter_list_node(syntax_node).unwrap();
                    let ranges = &parsed.ranges[&link.unit];
                    assert_eq!(ranges.len(), 1);
                    assert_eq!(ranges[0].end_byte, parameter_list.end_byte());
                    assert_eq!(ranges[0].end_line, parameter_list.end_position().row + 1);
                }
                _ => {}
            }
        }
        assert_eq!(parsed.source_declaration_metadata.len(), 8);
    }

    #[test]
    fn recovered_members_only_admit_direct_local_functions() {
        let source = "class C { void Broken( }\nvoid Kept() {}\nint detached;\nif (true) { void Nested() {} }";
        let tree = crate::preprocessor::parse_csharp(source).unwrap();
        assert!(tree.root_node().has_error());
        let mut found = Vec::new();
        let mut cursor = tree.root_node().walk();
        for statement in tree
            .root_node()
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "global_statement")
        {
            if let Some(member) = csharp_recovered_type_member(statement) {
                assert_eq!(member.kind(), "local_function_statement");
                assert_eq!(member.parent(), Some(statement));
                found.push(cs_node_text(
                    member.child_by_field_name("name").unwrap(),
                    source,
                ));
            }
        }
        assert_eq!(found, ["Kept"], "{}", tree.root_node().to_sexp());
    }
}
