use crate::imports::parse_ruby_load_syntax;
use crate::local_bindings::PrimaryLocalBindings;
use crate::mixins::{encode_mixin_relation, encode_superclass_relation, mixin_specs_for_call};
use crate::structural::{RUBY_STRUCTURAL_SPEC, is_nested_scope_root, is_value_read_position};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, DispatchExtensibility, RubyMethodDispatchMode, SignatureMetadata,
};
use brokk_bifrost_core::analyzer::parsed_file::{
    ParsedFile, ParsedSourceFacts, SourceDeclarationMetadataLink, SourceImportFact,
};
use brokk_bifrost_core::analyzer::ruby_facts::{RubyLoadFact, RubySourceFacts};
use brokk_bifrost_core::analyzer::rust_facts::RustItemSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceImportId,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::structural::materialization::{
    GenerationKind, MaterializationRecord,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    ParentIndex, WalkControl, node_range, walk_named_tree_preorder,
};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser, Tree};

/// Intern one qualified-name segment in the process-global interner.
fn ruby_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Build the structured type/namespace chain for a sequence of Ruby class/
/// module name segments (already atomic AST-derived strings — see
/// [`extract_name_segments`], which walks `scope_resolution` nodes rather than
/// splitting `A::B` text). Ruby's `package_name` is always empty and its legacy
/// `short_name` joins EVERY namespace segment with a literal `$` (see this
/// module's doc comment on [`RubyVisitor`]): `module A; class B` yields `A$B`.
/// [`SegmentKind::Nested`] is the tag whose join renders a leading
/// `$` regardless of the previous segment's kind, and the very first segment of
/// a qualified name never gets a leading separator at all (there is no
/// preceding segment) — so tagging every namespace segment `Companion`
/// reproduces the `$`-joined chain exactly, including its first element.
fn ruby_type_chain_fq(segments: &[String]) -> FqName {
    let mut fq = FqName::new();
    for segment in segments {
        fq.push(ruby_segment(segment, SegmentKind::Nested));
    }
    fq
}

/// Extends a type/namespace chain with one trailing `Member` segment — the
/// structured counterpart of [`member_short_name`], which appends `.name`
/// after the `$`-joined chain.
fn ruby_member_fq(type_segments: &[String], name: &str) -> FqName {
    ruby_type_chain_fq(type_segments).with_pushed(ruby_segment(name, SegmentKind::Member))
}

/// Parses Ruby source into a tree-sitter tree, or `None` if parsing fails.
pub fn parse_ruby_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ruby::LANGUAGE.into())
        .expect("failed to load ruby parser");
    parser.parse(source, None)
}

/// Reads the source text backing a tree-sitter node.
pub fn ruby_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

/// Walks a Ruby file and emits its declarations into `parsed`.
///
/// Ruby symbol identity follows the shared `CodeUnit` scheme used by every
/// bifrost analyzer: `package_name` is empty, nested namespaces/types are joined
/// in `short_name` with `$`, and a type's members are appended after a `.`. So
/// `module A; class B; def c` yields `A$B` (class) and `A$B.c` (method), which
/// `CodeUnit::identifier` resolves back to `B` and `c`.
pub struct RubyVisitor<'a> {
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub parsed: &'a mut ParsedFile,
    pub source_facts: PrimarySourceFactCollector<'a>,
    pub imports: Vec<SourceImportFact>,
    pub import_by_node: HashMap<usize, SourceImportId>,
    pub generic_imports: Vec<SourceImportId>,
    pub ruby: RubySourceFacts,
    pub field_contexts: HashMap<usize, usize>,
    pub field_owners: Vec<RubyFieldContext>,
    pub current_module: Option<usize>,
    pub module_functions: HashMap<usize, RubyModuleFunctions>,
    pub pending_dispatch: Vec<RubyPendingDispatch>,
    pub mixin_roots: HashMap<usize, usize>,
    pub mixin_containers: Vec<RubyMixinContainer>,
}

/// A pending traversal step: visit `node` as a statement within the enclosing
/// type's `segments`/`parent` context. The visitor uses an explicit stack of
/// these instead of native recursion so deeply nested input cannot overflow the
/// call stack (per AGENTS.md, and mirroring the Python visitor).
struct RubyWork<'tree> {
    node: Node<'tree>,
    segments: Vec<String>,
    parent: Option<CodeUnit>,
}

#[derive(Default)]
pub struct RubyMixinContainer {
    owner: Option<(CodeUnit, Vec<(String, String)>)>,
    relations: Vec<(String, String)>,
    children: Vec<usize>,
}

#[derive(Default)]
pub struct RubyModuleFunctions {
    bare_start: Option<usize>,
    names: HashSet<String>,
}

pub struct RubyPendingDispatch {
    unit: CodeUnit,
    module: Option<usize>,
    name: String,
    start: usize,
    mode: RubyMethodDispatchMode,
}

#[derive(Clone)]
pub struct RubyFieldContext {
    segments: Vec<String>,
    parent: Option<CodeUnit>,
    scope: RubyFieldScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RubyFieldScope {
    Instance,
    ClassVariable,
    SingletonClass,
}

/// Pushes a node's named children as statement work items. Children are pushed
/// in reverse so the stack pops them in source order.
fn push_named_children<'tree>(
    node: Node<'tree>,
    segments: &[String],
    parent: Option<&CodeUnit>,
    stack: &mut Vec<RubyWork<'tree>>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push(RubyWork {
            node: child,
            segments: segments.to_vec(),
            parent: parent.cloned(),
        });
    }
}

impl RubyVisitor<'_> {
    pub fn visit_program(mut self, root: Node<'_>) {
        self.ruby.has_parse_errors = root.has_error();
        let spec = &RUBY_STRUCTURAL_SPEC;
        let kinds = CompiledKinds::compile(&tree_sitter_ruby::LANGUAGE.into(), spec.kind_table());
        let context = CallSiteContext::default();
        let mut bindings = PrimaryLocalBindings::default();
        let root_bindings = bindings.enter_scope(self.source, root, None);
        let mut structural = StructuralFactCollector::new(
            spec,
            self.source,
            &context,
            ParentIndex::new(root),
            usize::MAX,
            None,
        );
        let mut pending = Vec::new();
        push_named_children(root, &[], None, &mut pending);
        let mut statements: HashMap<usize, RubyWork<'_>> = pending
            .drain(..)
            .map(|work| (work.node.id(), work))
            .collect();
        let mut lexical_scopes = vec![Vec::<String>::new()];
        let mut walk = vec![(
            root,
            None,
            None::<usize>,
            root_bindings,
            0usize,
            None::<usize>,
            None::<usize>,
        )];
        while let Some((
            node,
            parent,
            mut fields,
            inherited_bindings,
            mut lexical_scope,
            mut module,
            mut mixin,
        )) = walk.pop()
        {
            if matches!(node.kind(), "class" | "module")
                && let Some(name) = node.child_by_field_name("name")
            {
                let mut segments = lexical_scopes[lexical_scope].clone();
                segments.extend(extract_name_segments(name, self.source));
                lexical_scope = lexical_scopes.len();
                lexical_scopes.push(segments);
            }
            if let Some(root) = self.mixin_roots.remove(&node.id()) {
                mixin = Some(root);
            } else if let Some(container) = mixin {
                if node.kind() == "call" {
                    self.mixin_containers[container].relations.extend(
                        mixin_specs_for_call(node, self.source)
                            .into_iter()
                            .map(|spec| {
                                let encoded = encode_mixin_relation(&spec);
                                (spec.raw_target, encoded)
                            }),
                    );
                    mixin = None;
                } else if is_descendable_container(node.kind()) {
                    let child = self.mixin_containers.len();
                    self.mixin_containers.push(RubyMixinContainer::default());
                    self.mixin_containers[container].children.push(child);
                    mixin = Some(child);
                } else {
                    mixin = None;
                }
            }
            self.current_module = module;
            match node.kind() {
                "module" => {
                    module = Some(node.id());
                }
                "class" | "method" | "singleton_method" => {
                    module = None;
                }
                _ => {}
            }
            if let Some(owner) = module {
                let names = if node.kind() == "call"
                    && node.child_by_field_name("method").is_some_and(|method| {
                        ruby_node_text(method, self.source).trim() == "module_function"
                    }) {
                    Some(module_function_names(node, self.source).collect::<Vec<_>>())
                } else if node.kind() == "identifier"
                    && ruby_node_text(node, self.source).trim() == "module_function"
                {
                    Some(Vec::new())
                } else {
                    None
                };
                if let Some(names) = names {
                    let facts = self.module_functions.entry(owner).or_default();
                    if names.is_empty() {
                        facts.bare_start = Some(
                            facts
                                .bare_start
                                .map_or(node.start_byte(), |start| start.min(node.start_byte())),
                        );
                    } else {
                        facts.names.extend(names);
                    }
                    module = None;
                }
            }
            let load_syntax = parse_ruby_load_syntax(node, self.source);
            self.ruby.has_parse_errors |= node.is_error() || node.is_missing();
            if let Some(boundary) = crate::diagnostics::runtime_boundary_for_node(
                node,
                self.source,
                load_syntax.as_ref(),
            ) {
                // Preserve the old right-to-left preorder boundary selection:
                // later sibling extents win, and an ancestor precedes its children.
                let range = node_range(node);
                if self.ruby.runtime_boundary.is_none_or(|(occurrence, _)| {
                    let previous = self.source_facts.occurrence(occurrence).range;
                    (range.end_byte, std::cmp::Reverse(range.start_byte))
                        > (previous.end_byte, std::cmp::Reverse(previous.start_byte))
                }) {
                    self.ruby.runtime_boundary =
                        Some((self.source_facts.intern_node(node), boundary));
                }
            }
            if let Some(syntax) = load_syntax {
                let import = SourceImportId::try_from_index(self.imports.len())
                    .expect("Ruby import ids fit u32");
                let declaration = self.source_facts.intern_node(node);
                let target = self.source_facts.intern_node(syntax.target);
                self.imports.push(SourceImportFact::from_import(
                    syntax.import,
                    declaration,
                    Some(target),
                    None,
                    Vec::new(),
                ));
                self.import_by_node.insert(node.id(), import);
                self.ruby.loads.push(RubyLoadFact {
                    import,
                    kind: syntax.kind,
                    has_receiver: syntax.has_receiver,
                    autoload_constant: syntax.constant.map(|constant| {
                        let mut name = lexical_scopes[lexical_scope].clone();
                        name.push(constant);
                        name
                    }),
                });
            }
            let binding_scope = if node != root && is_nested_scope_root(node) {
                bindings.enter_scope(self.source, node, Some(inherited_bindings))
            } else {
                inherited_bindings
            };
            bindings.observe(self.source, binding_scope, node);
            if matches!(node.kind(), "identifier" | "constant") {
                let text = ruby_node_text(node, self.source).trim();
                if !text.is_empty() {
                    self.parsed.type_identifiers.insert(text.to_owned());
                }
            }
            let mut structural_parent = parent;
            if let Some(raw_kind) = kinds.kind_of(&node)
                && spec.should_extract(node, raw_kind)
            {
                let kind = if node.kind() == "identifier"
                    && is_value_read_position(node)
                    && !bindings.is_active(
                        binding_scope,
                        ruby_node_text(node, self.source),
                        node.start_byte(),
                    ) {
                    NormalizedKind::Call
                } else {
                    spec.refine_kind(
                        node,
                        raw_kind,
                        parent.map(|id| structural.normalized_kind(id)),
                        self.source,
                        &context,
                    )
                };
                let fact = structural
                    .enter(node, kind, parent, &mut self.source_facts)
                    .expect("Ruby structural collection is unbounded");
                let mut sink = structural.role_sink(&mut self.source_facts);
                spec.extract(node, kind, &mut sink);
                structural
                    .accept_roles(fact, sink.into_parts())
                    .expect("Ruby structural roles are unbounded");
                structural_parent = Some(fact);
            }
            if matches!(
                node.kind(),
                "class" | "module" | "method" | "singleton_method" | "singleton_class"
            ) {
                fields = None;
            }
            let field_assignment =
                matches!(node.kind(), "assignment" | "operator_assignment") && fields.is_some();
            if let Some(index) = fields.filter(|_| field_assignment) {
                let context = self.field_owners[index].clone();
                self.visit_assignment(
                    node,
                    &context.segments,
                    context.parent.as_ref(),
                    Some(context.scope),
                );
            }
            if let Some(work) = statements.remove(&node.id()) {
                if !field_assignment {
                    self.visit_statement(node, &work.segments, work.parent.as_ref(), &mut pending);
                }
                statements.extend(pending.drain(..).map(|work| (work.node.id(), work)));
            }
            if let Some(context) = self.field_contexts.remove(&node.id()) {
                fields = Some(context);
            }
            // A field assignment is one declaration; its expression children
            // do not introduce additional field declarations in this projection.
            if matches!(node.kind(), "assignment" | "operator_assignment") {
                fields = None;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    walk.push((
                        child,
                        structural_parent,
                        fields,
                        binding_scope,
                        lexical_scope,
                        module,
                        mixin,
                    ));
                }
            }
        }
        assert!(
            statements.is_empty(),
            "Ruby statement admission must follow primary nodes"
        );
        for root in 0..self.mixin_containers.len() {
            let Some((owner, mut relations)) = self.mixin_containers[root].owner.take() else {
                continue;
            };
            if !self.parsed.contains_declaration(&owner) {
                continue;
            }
            let mut pending = vec![root];
            while let Some(container) = pending.pop() {
                relations.append(&mut self.mixin_containers[container].relations);
                pending.extend(self.mixin_containers[container].children.iter().copied());
            }
            if relations.is_empty() {
                self.parsed.raw_supertypes.remove(&owner);
                self.parsed.supertype_lookup_paths.remove(&owner);
            } else {
                self.parsed.set_raw_supertypes(
                    owner.clone(),
                    relations.iter().map(|(raw, _)| raw.clone()).collect(),
                );
                self.parsed.set_supertype_lookup_paths(
                    owner,
                    relations.into_iter().map(|(_, encoded)| encoded).collect(),
                );
            }
        }
        for pending in self.pending_dispatch {
            if !self.parsed.contains_declaration(&pending.unit) {
                continue;
            }
            let mode = if pending
                .module
                .and_then(|module| self.module_functions.get(&module))
                .is_some_and(|facts| {
                    facts.names.contains(&pending.name)
                        || facts.bare_start.is_some_and(|start| start < pending.start)
                }) {
                RubyMethodDispatchMode::ModuleFunction
            } else {
                pending.mode
            };
            self.parsed
                .set_ruby_method_dispatch_mode(pending.unit, mode);
        }
        let occurrences = self.source_facts.finish();
        self.parsed.imports = self
            .generic_imports
            .iter()
            .map(|id| self.imports[id.index()].import_info(&occurrences))
            .collect();
        self.parsed.source_facts = Some(ParsedSourceFacts {
            cpp: None,
            go: None,
            java: None,
            js_ts: None,
            ruby: Some(self.ruby),
            php: None,
            scala: None,
            python: None,
            source_bytes: self.source.len(),
            occurrences,
            structural: structural
                .finish()
                .expect("Ruby structural collection must finish"),
            native_site_occurrences: Vec::new(),
            native_declaration_sources: Vec::new(),
            declaration_visibilities: None,
            rust_declaration_properties: Vec::new(),
            rust_modules: None,
            rust_types: Vec::new(),
            rust_items: RustItemSourceFacts::default(),
            generic_imports: self.generic_imports,
            imports: self.imports,
            rust_import_contexts: Vec::new(),
        });
    }

    fn record_declaration(
        &mut self,
        node: Node<'_>,
        name: Option<Node<'_>>,
        unit: CodeUnit,
    ) -> SourceDeclarationId {
        let occurrence = self.source_facts.intern_node(node);
        let name = name.map(|name| self.source_facts.intern_node(name));
        let declaration = self.source_facts.declare(occurrence, name);
        self.parsed
            .source_declaration_units
            .push((declaration, unit));
        declaration
    }

    fn visit_statement<'tree>(
        &mut self,
        node: Node<'tree>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        stack: &mut Vec<RubyWork<'tree>>,
    ) {
        match node.kind() {
            "class" => self.visit_class_like(node, segments, parent, false, stack),
            "module" => self.visit_class_like(node, segments, parent, true, stack),
            "singleton_class" => {
                // `class << self` — its methods belong to the enclosing type.
                if let Some(body) = node.child_by_field_name("body") {
                    push_named_children(body, segments, parent, stack);
                }
            }
            "method" | "singleton_method" => self.visit_method(node, segments, parent),
            "assignment" | "operator_assignment" => {
                self.visit_assignment(node, segments, parent, None)
            }
            "call" => self.visit_call(node, segments, parent),
            kind if is_descendable_container(kind) => {
                push_named_children(node, segments, parent, stack);
            }
            _ => {}
        }
    }

    fn visit_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        is_module: bool,
        stack: &mut Vec<RubyWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name_segments = extract_name_segments(name_node, self.source);
        if name_segments.is_empty() {
            return;
        }

        let mut new_segments = segments.to_vec();
        new_segments.extend(name_segments);
        let short_name = new_segments.join("$");

        let kind = if is_module {
            CodeUnitType::Module
        } else {
            CodeUnitType::Class
        };
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            kind,
            String::new(),
            short_name,
            ruby_type_chain_fq(&new_segments),
        );
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.record_declaration(node, Some(name_node), code_unit.clone());
        self.parsed
            .add_signature(code_unit.clone(), first_line(node, self.source));

        let owner_relations = extract_ruby_supertypes(node, self.source)
            .into_iter()
            .map(|target| {
                let encoded = encode_superclass_relation(&target);
                (target, encoded)
            })
            .collect();
        let root = self.mixin_containers.len();
        self.mixin_containers.push(RubyMixinContainer {
            owner: Some((code_unit.clone(), owner_relations)),
            ..Default::default()
        });
        if let Some(body) = node.child_by_field_name("body") {
            self.mixin_roots.insert(body.id(), root);
        }

        self.field_contexts
            .insert(node.id(), self.field_owners.len());
        self.field_owners.push(RubyFieldContext {
            segments: new_segments.clone(),
            parent: Some(code_unit.clone()),
            scope: RubyFieldScope::SingletonClass,
        });
        if let Some(body) = node.child_by_field_name("body") {
            push_named_children(body, &new_segments, Some(&code_unit), stack);
        }
    }

    fn visit_method(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = ruby_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let short_name = member_short_name(segments, name);
        let signature = node
            .child_by_field_name("parameters")
            .map(|params| ruby_node_text(params, self.source).trim().to_string());
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Function,
            String::new(),
            short_name,
            signature,
            false,
            ruby_member_fq(segments, name),
        );
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        let declaration = self.record_declaration(node, Some(name_node), code_unit.clone());
        self.pending_dispatch.push(RubyPendingDispatch {
            unit: code_unit.clone(),
            module: (node.kind() == "method")
                .then_some(self.current_module)
                .flatten(),
            name: name.to_owned(),
            start: node.start_byte(),
            mode: ruby_method_dispatch_mode(node),
        });
        let metadata_ordinal = self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            ruby_signature_metadata(first_line(node, self.source), node, self.source),
        );
        self.parsed
            .source_declaration_metadata
            .push(SourceDeclarationMetadataLink {
                declaration,
                unit: code_unit,
                metadata_ordinal,
            });
        // Method bodies are otherwise leaves for declaration purposes, but Ruby
        // instance/class variables are declarations even when first assigned in
        // methods.
        self.field_contexts
            .insert(node.id(), self.field_owners.len());
        self.field_owners.push(RubyFieldContext {
            segments: segments.to_vec(),
            parent: parent.cloned(),
            scope: ruby_method_field_scope(node),
        });
    }

    fn visit_assignment(
        &mut self,
        node: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        field_scope: Option<RubyFieldScope>,
    ) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if let Some(field_scope) = ruby_field_scope_for_assignment_left(left, segments, field_scope)
        {
            self.visit_variable_field_assignment(node, left, segments, parent, field_scope);
            return;
        }
        // Only constant assignments are declarations; locals are lowercase.
        if !matches!(left.kind(), "constant" | "scope_resolution") {
            return;
        }
        let name_path = extract_name_path(left, self.source);
        if name_path.segments.is_empty() {
            return;
        }
        let short_name = assignment_constant_short_name(segments, &name_path);
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            String::new(),
            short_name,
            assignment_constant_fq(segments, &name_path),
        );
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.record_declaration(node, Some(left), code_unit.clone());
        self.parsed.add_signature(
            code_unit,
            ruby_node_text(node, self.source).trim().to_string(),
        );
    }

    fn visit_variable_field_assignment(
        &mut self,
        node: Node<'_>,
        left: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
        field_scope: RubyFieldScope,
    ) {
        let Some(short_name) = ruby_field_short_name(segments, left, self.source, field_scope)
        else {
            return;
        };
        let fq = ruby_field_fq(segments, left, self.source, field_scope).unwrap_or_default();
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            String::new(),
            short_name,
            fq,
        );
        if self
            .parsed
            .first_range_start(&code_unit)
            .is_some_and(|start| start <= node.start_byte())
        {
            return;
        }
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        self.record_declaration(node, Some(left), code_unit.clone());
        self.parsed.add_signature(
            code_unit,
            ruby_node_text(node, self.source).trim().to_string(),
        );
    }

    fn visit_call(&mut self, node: Node<'_>, segments: &[String], parent: Option<&CodeUnit>) {
        let Some(method) = node.child_by_field_name("method") else {
            return;
        };
        let method_name = ruby_node_text(method, self.source).trim();
        match method_name {
            "require" | "require_relative" | "load" | "autoload" => {
                if let Some(import) = self.import_by_node.get(&node.id()) {
                    self.generic_imports.push(*import);
                }
            }
            "attr_accessor" | "attr_reader" | "attr_writer" => {
                self.visit_attr_macro(node, method_name, segments, parent);
            }
            "alias_method" => {
                self.visit_alias_method(node, segments, parent);
            }
            _ => {}
        }
    }

    fn visit_attr_macro(
        &mut self,
        node: Node<'_>,
        method_name: &str,
        segments: &[String],
        parent: Option<&CodeUnit>,
    ) {
        // `attr_accessor` and friends only declare members inside a type body.
        let Some(parent) = parent else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let mut dynamic_argument_seen = false;
        for arg in arguments.named_children(&mut cursor) {
            let Some(name) = literal_symbol_or_string_name(arg, self.source) else {
                // A non-literal argument generates *something* the analyzer
                // cannot name. The site record is what keeps the generated
                // set explicitly unknown rather than silently empty.
                dynamic_argument_seen = true;
                continue;
            };
            let member_name = attr_field_member_name(node, &name);
            let field_name = format!("@{name}");
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                String::new(),
                member_short_name(segments, &member_name),
                ruby_scoped_field_fq(segments, &field_name, method_is_singleton_context(node)),
            );
            self.parsed.replace_code_unit(
                code_unit.clone(),
                node,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.record_declaration(node, Some(arg), code_unit.clone());
            self.parsed
                .record_materialization(MaterializationRecord::GeneratedDeclaration {
                    site: node_range(node),
                    argument: node_range(arg),
                    kind: GenerationKind::AccessorMacro,
                    unit: code_unit.clone(),
                });
            self.parsed.add_signature(
                code_unit,
                ruby_node_text(node, self.source).trim().to_string(),
            );
            if matches!(method_name, "attr_accessor" | "attr_reader") {
                self.add_member_function(
                    node,
                    arg,
                    segments,
                    parent,
                    &name,
                    GenerationKind::AccessorMacro,
                );
            }
            if matches!(method_name, "attr_accessor" | "attr_writer") {
                self.add_member_function(
                    node,
                    arg,
                    segments,
                    parent,
                    &format!("{name}="),
                    GenerationKind::AccessorMacro,
                );
            }
        }
        if dynamic_argument_seen {
            self.parsed
                .record_materialization(MaterializationRecord::DynamicGenerationSite {
                    site: node_range(node),
                    kind: GenerationKind::AccessorMacro,
                });
        }
    }

    fn visit_alias_method(
        &mut self,
        node: Node<'_>,
        segments: &[String],
        parent: Option<&CodeUnit>,
    ) {
        let Some(parent) = parent else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let Some(alias_arg) = arguments.named_children(&mut cursor).next() else {
            return;
        };
        let Some(alias_name) = literal_symbol_or_string_name(alias_arg, self.source) else {
            // A dynamic alias name generates a method the analyzer cannot
            // name; record the site so the generated set stays explicitly
            // unknown.
            self.parsed
                .record_materialization(MaterializationRecord::DynamicGenerationSite {
                    site: node_range(node),
                    kind: GenerationKind::AliasMacro,
                });
            return;
        };
        self.add_member_function(
            node,
            alias_arg,
            segments,
            parent,
            &alias_name,
            GenerationKind::AliasMacro,
        );
    }

    fn add_member_function(
        &mut self,
        signature_node: Node<'_>,
        range_node: Node<'_>,
        segments: &[String],
        parent: &CodeUnit,
        name: &str,
        generation: GenerationKind,
    ) {
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Function,
            String::new(),
            member_short_name(segments, name),
            ruby_member_fq(segments, name),
        );
        self.parsed.replace_code_unit(
            code_unit.clone(),
            range_node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.record_declaration(range_node, Some(range_node), code_unit.clone());
        self.parsed
            .record_materialization(MaterializationRecord::GeneratedDeclaration {
                site: node_range(signature_node),
                argument: node_range(range_node),
                kind: generation,
                unit: code_unit.clone(),
            });
        self.pending_dispatch.push(RubyPendingDispatch {
            unit: code_unit.clone(),
            module: None,
            name: name.to_owned(),
            start: signature_node.start_byte(),
            mode: ruby_method_dispatch_mode(signature_node),
        });
        self.parsed.add_signature(
            code_unit,
            ruby_node_text(signature_node, self.source)
                .trim()
                .to_string(),
        );
    }
}

/// Builds a member's `short_name` from its enclosing type segments and own name.
fn member_short_name(segments: &[String], name: &str) -> String {
    if segments.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", segments.join("$"), name)
    }
}

fn attr_field_member_name(node: Node<'_>, name: &str) -> String {
    if method_is_singleton_context(node) {
        format!("$singleton.@{name}")
    } else {
        format!("@{name}")
    }
}

pub fn ruby_variable_field_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "instance_variable" | "class_variable") {
        return None;
    }
    let name = ruby_node_text(node, source).trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// The rendered member tail shared by [`ruby_field_short_name`] and
/// [`ruby_field_fq`]. Singleton-scoped fields retain the established
/// `$singleton.@field` spelling, while [`ruby_field_fq`] records `$singleton`
/// and the field itself as distinct scope/member segments.
fn ruby_field_member_name(node: Node<'_>, source: &str, scope: RubyFieldScope) -> Option<String> {
    let name = ruby_variable_field_name(node, source)?;
    Some(match scope {
        RubyFieldScope::Instance | RubyFieldScope::ClassVariable => name,
        RubyFieldScope::SingletonClass => format!("$singleton.{name}"),
    })
}

pub fn ruby_field_short_name(
    segments: &[String],
    node: Node<'_>,
    source: &str,
    scope: RubyFieldScope,
) -> Option<String> {
    if segments.is_empty() {
        return None;
    }
    let member = ruby_field_member_name(node, source, scope)?;
    Some(member_short_name(segments, &member))
}

/// The structured counterpart of [`ruby_field_short_name`].
fn ruby_field_fq(
    segments: &[String],
    node: Node<'_>,
    source: &str,
    scope: RubyFieldScope,
) -> Option<FqName> {
    if segments.is_empty() {
        return None;
    }
    let name = ruby_variable_field_name(node, source)?;
    Some(ruby_scoped_field_fq(
        segments,
        &name,
        scope == RubyFieldScope::SingletonClass,
    ))
}

/// Builds the structured identity for a Ruby field. `$singleton` is a real
/// synthetic owner scope, not part of the terminal field identifier.
fn ruby_scoped_field_fq(segments: &[String], name: &str, singleton: bool) -> FqName {
    let mut fq = ruby_type_chain_fq(segments);
    if singleton {
        fq.push(ruby_segment("$singleton", SegmentKind::Package));
    }
    fq.push(ruby_segment(name, SegmentKind::Member));
    fq
}

pub fn ruby_field_scope_for_assignment_left(
    left: Node<'_>,
    segments: &[String],
    current_scope: Option<RubyFieldScope>,
) -> Option<RubyFieldScope> {
    if segments.is_empty() {
        return None;
    }
    match left.kind() {
        "class_variable" => Some(RubyFieldScope::ClassVariable),
        "instance_variable" => Some(current_scope.unwrap_or(RubyFieldScope::SingletonClass)),
        _ => None,
    }
}

fn ruby_method_field_scope(node: Node<'_>) -> RubyFieldScope {
    if method_is_singleton_context(node) {
        RubyFieldScope::SingletonClass
    } else {
        RubyFieldScope::Instance
    }
}

fn ruby_method_dispatch_mode(node: Node<'_>) -> RubyMethodDispatchMode {
    if method_is_singleton_context(node) {
        RubyMethodDispatchMode::Singleton
    } else {
        RubyMethodDispatchMode::Instance
    }
}

fn method_is_singleton_context(node: Node<'_>) -> bool {
    if node.kind() == "singleton_method" {
        return true;
    }
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == "singleton_class" {
            return true;
        }
        if matches!(current.kind(), "class" | "module") {
            break;
        }
        parent = current.parent();
    }
    false
}

fn module_function_names<'a>(node: Node<'_>, source: &'a str) -> impl Iterator<Item = String> + 'a {
    let mut names = Vec::new();
    if let Some(arguments) = node.child_by_field_name("arguments") {
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            if let Some(name) = literal_symbol_or_string_name(arg, source) {
                names.push(name);
            }
        }
    }
    names.into_iter()
}

fn assignment_constant_short_name(lexical_segments: &[String], name_path: &RubyNamePath) -> String {
    let Some((name, owner_segments)) = name_path.segments.split_last() else {
        return String::new();
    };
    if owner_segments.is_empty() {
        return member_short_name(lexical_segments, name);
    }
    if name_path.absolute || owner_segments.len() > 1 || lexical_segments.is_empty() {
        return member_short_name(owner_segments, name);
    }

    let mut resolved_owner = Vec::new();
    resolved_owner.extend_from_slice(lexical_segments);
    resolved_owner.extend_from_slice(owner_segments);
    member_short_name(&resolved_owner, name)
}

/// The structured counterpart of [`assignment_constant_short_name`] — mirrors
/// its branches exactly, building an [`FqName`] from the same owner segments
/// instead of a `$`-joined string. The owner segments come from the constant
/// reference's own AST-derived name path (`extract_name_path`), which may name
/// a different (re-opened) namespace than the lexically enclosing one, so this
/// builds a fresh chain rather than extending a `parent` `CodeUnit`'s `fq`.
fn assignment_constant_fq(lexical_segments: &[String], name_path: &RubyNamePath) -> FqName {
    let Some((name, owner_segments)) = name_path.segments.split_last() else {
        return FqName::new();
    };
    if owner_segments.is_empty() {
        return ruby_member_fq(lexical_segments, name);
    }
    if name_path.absolute || owner_segments.len() > 1 || lexical_segments.is_empty() {
        return ruby_member_fq(owner_segments, name);
    }

    let mut resolved_owner = Vec::new();
    resolved_owner.extend_from_slice(lexical_segments);
    resolved_owner.extend_from_slice(owner_segments);
    ruby_member_fq(&resolved_owner, name)
}

pub struct RubyNamePath {
    pub segments: Vec<String>,
    pub absolute: bool,
}

/// Extracts the namespace segments from a class/module name node by walking the
/// AST (not by string-splitting `::`). A plain `(constant)` yields one segment;
/// a `(scope_resolution)` like `A::B` walks its `scope` and `name` fields to
/// yield `["A", "B"]`.
pub fn extract_name_segments(name_node: Node<'_>, source: &str) -> Vec<String> {
    extract_name_path(name_node, source).segments
}

pub fn extract_name_path(name_node: Node<'_>, source: &str) -> RubyNamePath {
    let mut path = RubyNamePath {
        segments: Vec::new(),
        absolute: false,
    };
    let mut stack = vec![name_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "scope_resolution" {
            if let Some(name) = node.child_by_field_name("name") {
                stack.push(name);
            }
            if let Some(scope) = node.child_by_field_name("scope") {
                stack.push(scope);
            } else if path.segments.is_empty() {
                path.absolute = true;
            }
        } else {
            let text = ruby_node_text(node, source).trim();
            if !text.is_empty() {
                path.segments.push(text.to_owned());
            }
        }
    }
    path
}

/// Renders a `constant`/`scope_resolution` reference node into the internal
/// `$`-joined name used as a `CodeUnit` key (e.g. `A::B` -> `A$B`).
pub fn qualified_internal_name(node: Node<'_>, source: &str) -> Option<String> {
    let segments = extract_name_segments(node, source);
    (!segments.is_empty()).then(|| segments.join("$"))
}

/// Collects a class/module's true superclass. Ruby mixins are intentionally not
/// type hierarchy ancestors; they are modeled separately for method lookup.
fn extract_ruby_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut supertypes = Vec::new();

    if let Some(superclass) = node.child_by_field_name("superclass") {
        let mut cursor = superclass.walk();
        if let Some(expr) = superclass.named_children(&mut cursor).next()
            && let Some(name) = qualified_internal_name(expr, source)
        {
            supertypes.push(name);
        }
    }

    supertypes
}

/// Extracts the bare name from a literal `attr_*`/`alias_method` argument,
/// which is usually a symbol (`:name`) or string (`"name"`).
fn literal_symbol_or_string_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "simple_symbol" | "string") {
        return None;
    }
    let text = ruby_node_text(node, source).trim();
    let stripped = text
        .strip_prefix(':')
        .unwrap_or(text)
        .trim_matches(['"', '\'']);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

/// First non-blank line of a node's source, used as a one-line signature.
fn first_line(node: Node<'_>, source: &str) -> String {
    ruby_node_text(node, source)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// The one place Ruby builds callable signature metadata for a `def`, so no
/// declaration path can record parameter labels and forget the modifier facts
/// that make the callable keyable for procedure-summary binding (#2912):
/// `receiver_contract_of` refuses to answer for a callable whose adapter never
/// inspected modifiers.
///
/// A `singleton_method` (`def self.name`) and a `method` inside a
/// `class << self` body bind no instance receiver, which is what the receiver
/// contract calls static; [`method_is_singleton_context`] reads exactly those
/// two shapes. An ordinary `method` in a class or module body takes `self`. A
/// `def` at file scope is an instance method of `Object`, so it is not static
/// either; it has no type owner, and the contract falls out of that. Ruby has
/// no constructor declaration shape (`initialize` is an ordinary instance
/// method) and spells visibility as a method call rather than a modifier node,
/// so those two facts stay `false` and `Unknown`.
fn ruby_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let labels = match node.child_by_field_name("parameters") {
        Some(parameters_node) => {
            let mut cursor = parameters_node.walk();
            parameters_node
                .named_children(&mut cursor)
                .filter_map(|child| ruby_parameter_label_node(child))
                .map(|label_node| ruby_node_text(label_node, source).trim().to_string())
                .filter(|label| !label.is_empty())
                .collect()
        }
        None => Vec::new(),
    };
    SignatureMetadata::with_parameter_labels(signature, labels)
        .with_dispatch_extensibility(DispatchExtensibility::Open)
        .with_callable_modifiers(
            method_is_singleton_context(node),
            false,
            DeclaredVisibility::Unknown,
        )
}

fn ruby_parameter_label_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "optional_parameter"
        | "keyword_parameter"
        | "splat_parameter"
        | "hash_splat_parameter"
        | "block_parameter" => node
            .child_by_field_name("name")
            .or_else(|| first_identifier_descendant(node)),
        _ => None,
    }
}

fn first_identifier_descendant(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier" {
            return Some(current);
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

/// Container node kinds the visitor recurses through to find conditionally
/// declared symbols (e.g. a `def` inside an `if`). Excludes `method`/
/// `singleton_method`, whose bodies are treated as leaves.
pub fn is_descendable_container(kind: &str) -> bool {
    matches!(
        kind,
        "if" | "unless"
            | "elsif"
            | "else"
            | "while"
            | "until"
            | "for"
            | "case"
            | "case_match"
            | "when"
            | "in_clause"
            | "begin"
            | "body_statement"
            | "do"
            | "do_block"
            | "block"
            | "then"
            | "ensure"
            | "rescue"
            | "parenthesized_statements"
            | "begin_block"
            | "end_block"
    )
}
pub fn collect_ruby_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    walk_named_tree_preorder(node, true, |node| {
        if matches!(node.kind(), "identifier" | "constant") {
            let text = ruby_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        WalkControl::Continue
    });
}

#[cfg(test)]
mod callable_modifier_tests {
    use super::*;
    use crate::adapter::parse_ruby_file;

    /// The Ruby half of #2912. `def self.name` and a `def` inside
    /// `class << self` bind no instance receiver; an ordinary `def` in a class
    /// or module body, `initialize` included, binds one; a `def` at file scope
    /// is an instance method of `Object` and is not static either. Every `def`
    /// states that the walk read its declaration shape.
    #[test]
    fn callable_metadata_records_ruby_singleton_structurally() {
        let source = "def top_level(value)\n  value\nend\n\nclass Widget\n  def initialize(spec)\n    @spec = spec\n  end\n\n  def self.build(spec)\n    new(spec)\n  end\n\n  def render(target)\n    target\n  end\n\n  class << self\n    def measure(target)\n      target\n    end\n  end\nend\n\nmodule Helpers\n  def helper\n  end\nend\n";
        let file = ProjectFile::new(std::env::temp_dir(), "widget.rb");
        let tree = parse_ruby_tree(source).expect("parse Ruby fixture");
        let parsed = parse_ruby_file(&file, source, &tree);

        let modifiers = |fq_name: &str| {
            let metadata = parsed
                .signature_metadata
                .iter()
                .find(|(unit, _)| unit.fq_name() == fq_name)
                .and_then(|(_, metadata)| metadata.first())
                .unwrap_or_else(|| {
                    panic!(
                        "missing Ruby callable {fq_name}; recorded {:?}",
                        parsed
                            .signature_metadata
                            .keys()
                            .map(CodeUnit::fq_name)
                            .collect::<Vec<_>>()
                    )
                });
            assert!(
                metadata.callable_modifiers_recorded(),
                "{fq_name} must record that the walk read its declaration shape"
            );
            (
                metadata.callable_is_static(),
                metadata.callable_is_constructor(),
                metadata.parameters().len(),
            )
        };

        assert_eq!(modifiers("top_level"), (false, false, 1));
        assert_eq!(modifiers("Widget.initialize"), (false, false, 1));
        assert_eq!(modifiers("Widget.build"), (true, false, 1));
        assert_eq!(modifiers("Widget.render"), (false, false, 1));
        assert_eq!(modifiers("Widget.measure"), (true, false, 1));
        assert_eq!(modifiers("Helpers.helper"), (false, false, 0));
    }
}
