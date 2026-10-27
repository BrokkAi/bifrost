use crate::scala::graph::syntax::callable_arity_for_parameters;
use crate::scala::structural::{
    SCALA_KIND_TABLE, SCALA_STRUCTURAL_SPEC, is_case_class as scala_structural_is_case_class,
};
use crate::scala::syntax::node_text as scala_node_text;
use brokk_bifrost_core::analyzer::canonical_hash::{hash_domain_bytes, lower_hex_string};
use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentId, SegmentKind, joined_segments, segment_interner,
};
use brokk_bifrost_core::analyzer::model::StructuredTypeIdentityBuilder;
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CallableOverrideModifier, CodeUnit, CodeUnitType, DispatchExtensibility,
    ParameterMetadata, ProjectFile, Range, SignatureMetadata, StructuredTypeIdentity,
    StructuredTypeName, child_fq_base,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::scala_facts::{
    ScalaDeclarationKind, ScalaDeclarationSourceFact, ScalaDeclarationVisibility,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceProvenance,
};
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_descendant_of_kind_inclusive, node_range,
};
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::{Node, Tree};

/// Build the structured package prefix for a Scala declaration.
///
/// A Scala `package_name` is the dotted package path (`com.example.experimental`),
/// each component a package. Each becomes a [`SegmentKind::Package`] segment so
/// the [`FqName`] renders back to the exact legacy `package_name` string.
/// Splitting the already-joined string here is the M1 bridge; the legacy string
/// stays authoritative until M3.
fn scala_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in joined_segments(package_name, ".") {
        fq.push(segment_interner().intern(component, SegmentKind::Package));
    }
    fq
}

fn scala_root_anonymous_name(source: &str, line: usize, column: usize) -> String {
    let source_id = lower_hex_string(&hash_domain_bytes(
        b"scala-root-anonymous-owner-v1",
        source.as_bytes(),
    ));
    format!("$anon${source_id}${line}:{column}")
}

/// The structured segment for a Scala type declaration's own name. A Scala
/// `object` is spelled with a trailing `$` on its own name (`Foo$`), captured
/// by a [`SegmentKind::Companion`] segment whose text is the bare name (the `$`
/// is added by the display rule); every other type kind is a [`SegmentKind::Type`].
fn scala_type_name_segment(raw_name: &str, is_object: bool) -> SegmentId {
    if is_object {
        segment_interner().intern(raw_name, SegmentKind::Companion)
    } else {
        segment_interner().intern(raw_name, SegmentKind::Type)
    }
}

use crate::scala::graph::syntax::ScalaPackageContextIndex;
use crate::scala::graph::syntax::scala_declared_type_parameter_names;
use crate::scala::imports::{scala_export_info_from_node, scala_lexical_scope_path};
use crate::scala::supertypes::{
    extract_scala_instance_supertypes, extract_scala_supertypes,
    scala_full_enum_case_owner_supertype,
};

pub fn parse_scala_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
    let mut parsed = brokk_bifrost_core::analyzer::parsed_file::ParsedFile::new(String::new());
    let mut collector = PrimarySourceFactCollector::new(source);
    let mut visitor = ScalaVisitor {
        file,
        source,
        parsed: &mut parsed,
        collector: &mut collector,
        scala_facts: Default::default(),
        captured_declarations: Default::default(),
        package_contexts: ScalaPackageContextIndex::new(tree.root_node(), source),
    };
    let root = tree.root_node();
    let grammar = crate::scala::language::LANGUAGE.into();
    let kinds = CompiledKinds::compile(&grammar, SCALA_KIND_TABLE);
    let context = SCALA_STRUCTURAL_SPEC.call_site_context(root, source);
    let mut structural = StructuralFactCollector::new(
        &SCALA_STRUCTURAL_SPEC,
        source,
        &context,
        brokk_bifrost_core::analyzer::tree_walk::ParentIndex::new(tree.root_node()),
        usize::MAX,
        None,
    );
    let mut pending = HashMap::<usize, Vec<ScalaWork<'_>>>::default();
    schedule_scala_work(
        vec![ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
            children: scala_compilation_children(root),
            index: 0,
            package_name: String::new(),
            package_prefixes: Vec::new(),
            recovery_owners: Vec::new(),
            unmatched_end_names: None,
        })],
        &mut pending,
    );
    let mut imports = Vec::new();
    let mut stack = vec![(root, None)];
    while let Some((node, enclosing)) = stack.pop() {
        if let Some(work) = pending.remove(&node.id()) {
            let mut scheduled = Vec::new();
            for work in work {
                match work {
                    ScalaWork::CompilationUnit(work) => {
                        visitor.process_compilation_unit(work, &mut scheduled)
                    }
                    ScalaWork::TemplateBody {
                        children,
                        index,
                        package_name,
                        package_prefixes,
                        parent,
                    } => visitor.process_template_body(
                        children,
                        index,
                        &package_name,
                        &package_prefixes,
                        &parent,
                        &mut scheduled,
                    ),
                }
            }
            schedule_scala_work(scheduled, &mut pending);
        }
        if matches!(
            node.kind(),
            "class_definition"
                | "full_enum_case"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "function_definition"
                | "function_declaration"
                | "val_definition"
                | "var_definition"
                | "val_declaration"
                | "var_declaration"
                | "class_parameter"
                | "type_definition"
        ) {
            let name = if matches!(
                node.kind(),
                "class_definition"
                    | "full_enum_case"
                    | "object_definition"
                    | "trait_definition"
                    | "enum_definition"
            ) {
                scala_type_declaration_name_node(node)
            } else {
                node.child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
            };
            visitor.capture(node, name);
        }
        if node.kind() == "instance_expression" && scala_anonymous_template_body(node).is_some() {
            let mut scheduled = Vec::new();
            visitor.visit_anonymous_class(node, &mut scheduled);
            schedule_scala_work(scheduled, &mut pending);
        }
        let mut parent = enclosing;
        if node.is_named()
            && let Some(kind) = kinds.kind_of(&node)
            && SCALA_STRUCTURAL_SPEC.should_extract(node, kind)
        {
            let kind = SCALA_STRUCTURAL_SPEC.refine_kind(
                node,
                kind,
                enclosing.map(|id| structural.normalized_kind(id)),
                source,
                &context,
            );
            let id = structural
                .enter(node, kind, enclosing, visitor.collector)
                .expect("complete Scala structural collection");
            let mut sink = structural.role_sink(visitor.collector);
            SCALA_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
            structural
                .accept_roles(id, sink.into_parts())
                .expect("complete Scala structural roles");
            parent = Some(id);
        }
        if node.kind() == "import_declaration" {
            let prefixes = visitor.package_contexts.prefixes_at(node.start_byte());
            imports.extend(crate::scala::imports::scala_source_imports_from_node(
                node,
                source,
                prefixes,
                visitor.collector,
            ));
        }
        if node.named_child_count() == 0
            && matches!(
                node.kind(),
                "identifier"
                    | "operator_identifier"
                    | "stable_identifier"
                    | "type_identifier"
                    | "stable_type_identifier"
            )
        {
            let name = scala_node_text(node, source).trim();
            if !name.is_empty() {
                visitor.parsed.type_identifiers.insert(name.to_string());
            }
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push((child, parent));
            }
        }
    }
    assert!(
        pending.is_empty(),
        "Scala declaration work must be reached by the primary walk"
    );
    let mut scala_facts = std::mem::take(&mut visitor.scala_facts);
    let native = crate::scala::resolution::extract_scala_resolution(
        root,
        source,
        visitor.parsed,
        &scala_facts,
        visitor.collector,
    );
    drop(visitor);
    let source_declarations = native
        .declaration_sources
        .iter()
        .map(|(site, declaration)| (*site, *declaration))
        .collect::<HashMap<_, _>>();
    for definition in &native.facts.definition_units {
        if !definition.unit.is_synthetic()
            || parsed
                .source_declaration_units
                .iter()
                .any(|(_, unit)| unit == &definition.unit)
        {
            continue;
        }
        let declaration = source_declarations[&definition.declaration];
        if native.facts.singleton_relations.iter().any(|relation| {
            relation.declaration == definition.declaration
                && relation.kind
                    == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSingletonRelationKind::Companion
        }) && !scala_facts
            .declarations
            .iter()
            .any(|fact| fact.declaration == declaration)
        {
            let class_source = native
                .facts
                .singleton_relations
                .iter()
                .find_map(|relation| {
                    (relation.declaration == definition.declaration
                        && relation.kind
                            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSingletonRelationKind::Companion)
                        .then_some(relation.enclosing_type)
                        .flatten()
                })
                .map(|site| source_declarations[&site])
                .expect("a synthesized companion has its case class owner");
            let mut companion_fact: ScalaDeclarationSourceFact = scala_facts
                .declarations
                .iter()
                .find(|fact| fact.declaration == class_source)
                .expect("a synthesized companion's case class has Scala source facts")
                .clone();
            companion_fact.declaration = declaration;
            companion_fact.kind = ScalaDeclarationKind::Object;
            companion_fact.callable = None;
            companion_fact.field_type_path = None;
            companion_fact.type_alias_path = None;
            companion_fact.stable_owner = true;
            companion_fact.is_enum = false;
            companion_fact.is_term_field = false;
            companion_fact.is_case_class = false;
            companion_fact.is_full_enum_case = false;
            companion_fact.is_abstract_callable = false;
            companion_fact.is_explicitly_abstract = false;
            companion_fact.is_sealed = false;
            companion_fact.is_final = true;
            companion_fact.generic_owner = None;
            scala_facts.declarations.push(companion_fact);
        }
        let parent = definition.unit.fq().parent().and_then(|fq| {
            parsed
                .declarations()
                .iter()
                .find(|unit| unit.fq() == &fq)
                .cloned()
        });
        parsed.add_synthetic_code_unit(definition.unit.clone(), parent, None);
        parsed
            .source_declaration_units
            .push((declaration, definition.unit.clone()));
    }
    let occurrences = collector.finish();
    parsed.resolution_facts = native.facts;
    parsed.imports = imports
        .iter()
        .map(|import| import.import_info(&occurrences))
        .collect();
    let generic_imports = (0..imports.len())
        .map(|index| {
            brokk_bifrost_core::analyzer::source_facts::SourceImportId::try_from_index(index)
                .expect("Scala import id")
        })
        .collect();
    parsed.source_facts = Some(ParsedSourceFacts {
        cpp: None,
        go: None,
        java: None,
        scala: Some(scala_facts),
        js_ts: None,
        php: None,
        ruby: None,
        python: None,
        source_bytes: source.len(),
        occurrences,
        structural: structural
            .finish(root)
            .expect("complete Scala structural collection"),
        native_site_occurrences: native.site_occurrences,
        native_declaration_sources: native.declaration_sources,
        declaration_visibilities: None,
        rust_declaration_properties: Vec::new(),
        rust_modules: None,
        rust_types: Vec::new(),
        rust_items: Default::default(),
        imports,
        generic_imports,
        rust_import_contexts: Vec::new(),
    });
    parsed
}

fn schedule_scala_work<'tree>(
    work: Vec<ScalaWork<'tree>>,
    pending: &mut HashMap<usize, Vec<ScalaWork<'tree>>>,
) {
    for work in work {
        let next = match &work {
            ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
                children, index, ..
            }) => children.get(*index),
            ScalaWork::TemplateBody {
                children, index, ..
            } => children.get(*index),
        };
        if let Some(next) = next {
            pending.entry(next.id()).or_default().push(work);
        }
    }
}

fn scala_compilation_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut named_cursor = node.walk();
    let mut children = node.named_children(&mut named_cursor).collect::<Vec<_>>();
    let mut token_cursor = node.walk();
    children.extend(
        node.children(&mut token_cursor)
            .filter(|child| !child.is_named() && child.kind() == "_end_ident"),
    );
    children.sort_unstable_by_key(Node::start_byte);
    children
}

struct ScalaVisitor<'a, 'source> {
    file: &'a ProjectFile,
    source: &'source str,
    parsed: &'a mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    collector: &'a mut PrimarySourceFactCollector<'source>,
    scala_facts: brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    captured_declarations: brokk_bifrost_core::hash::HashSet<SourceDeclarationId>,
    package_contexts: ScalaPackageContextIndex,
}

struct ScalaCompilationUnitWork<'tree> {
    children: Vec<Node<'tree>>,
    index: usize,
    package_name: String,
    package_prefixes: Vec<String>,
    recovery_owners: Vec<ScalaRecoveryOwner>,
    unmatched_end_names: Option<HashMap<String, usize>>,
}

enum ScalaWork<'tree> {
    CompilationUnit(ScalaCompilationUnitWork<'tree>),
    TemplateBody {
        children: Vec<Node<'tree>>,
        index: usize,
        package_name: String,
        package_prefixes: Vec<String>,
        parent: CodeUnit,
    },
}

#[derive(Clone)]
struct ScalaRecoveryOwner {
    declaration: CodeUnit,
    name: String,
    indentation: usize,
}

impl ScalaVisitor<'_, '_> {
    fn declare(
        &mut self,
        unit: &CodeUnit,
        node: Node<'_>,
        name: Option<Node<'_>>,
    ) -> SourceDeclarationId {
        let declaration = self.capture(node, name);
        self.parsed
            .source_declaration_units
            .push((declaration, unit.clone()));
        declaration
    }

    /// The [`CodeUnit`] of one Scala type-namespace declaration.
    ///
    /// Classes, traits, objects, and `type` aliases share one identity rule so
    /// a same-named term declared in the same owner can never mint the same
    /// unit: the declaration's own segment is [`scala_type_name_segment`]'s
    /// [`SegmentKind::Type`] (or [`SegmentKind::Companion`] for an `object`),
    /// which `declaration_id` hashes, and the unit is a
    /// [`CodeUnitType::Class`]. Minting an alias as a `Field`/`Member` made
    /// `object Tags { type MaxVal = Int; val MaxVal = 1 }` produce two
    /// byte-identical units and drop one declaration (#2878).
    fn scala_type_declaration_unit(
        &self,
        raw_name: &str,
        package_name: &str,
        parent: Option<&CodeUnit>,
        is_object: bool,
    ) -> CodeUnit {
        let display_name = if is_object {
            format!("{raw_name}$")
        } else {
            raw_name.to_string()
        };
        let short_name = parent.map_or_else(
            || display_name.clone(),
            |parent| format!("{}.{}", parent.short_name(), display_name),
        );
        let fq = child_fq_base(parent, || scala_package_fq(package_name))
            .with_pushed(scala_type_name_segment(raw_name, is_object));
        CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Class,
            package_name.to_string(),
            short_name,
            fq,
        )
    }

    fn capture(&mut self, node: Node<'_>, name: Option<Node<'_>>) -> SourceDeclarationId {
        let declaration = self.collector.declare_node(node, name);
        if self.captured_declarations.insert(declaration) {
            let mut fact = crate::scala::graph::syntax::scala_declaration_source_fact(
                node,
                self.source,
                declaration,
            );
            self.capture_declaration_context(node, &mut fact);
            self.scala_facts.declarations.push(fact);
        }
        declaration
    }

    fn capture_declaration_context(
        &mut self,
        node: Node<'_>,
        fact: &mut brokk_bifrost_core::analyzer::scala_facts::ScalaDeclarationSourceFact,
    ) {
        fact.lexical_prefixes = self
            .package_contexts
            .prefixes_at(node.start_byte())
            .to_vec();
        if let Some(qualifier) = crate::scala::graph::syntax::scala_access_qualifier(node) {
            use brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary;
            let name = scala_node_text(qualifier, self.source);
            if name != "this" {
                // A qualifier selects a lexical owner, never an ordinary type
                // alias or imported name. Innermost templates win.
                let mut ancestor = node.parent();
                while let Some(owner) = ancestor {
                    if matches!(
                        owner.kind(),
                        "class_definition"
                            | "trait_definition"
                            | "object_definition"
                            | "enum_definition"
                    ) && let Some(owner_name) = scala_type_declaration_name_node(owner)
                        && scala_node_text(owner_name, self.source) == name
                    {
                        fact.access_boundary = Some(DeclarationAccessBoundary::Template(
                            self.collector.declare_node(owner, Some(owner_name)),
                        ));
                        break;
                    }
                    ancestor = owner.parent();
                }
                if fact.access_boundary.is_none() {
                    let segments = self.package_contexts.package_segments_at(node.start_byte());
                    if let Some(position) = segments.iter().rposition(|segment| segment == name) {
                        fact.access_boundary = Some(DeclarationAccessBoundary::Package(
                            segments[..=position].join("."),
                        ));
                    }
                }
            }
        }
        // A declaration lookup occurs at its opening token, inside its own
        // lexical region, just as the previous point-syntax lookup observed.
        let mut current = Some(node);
        while let Some(parent) = current {
            if crate::scala::imports::is_scala_lexical_scope(parent.kind()) {
                fact.lexical_scopes.push(self.collector.intern_node(parent));
            }
            current = parent.parent();
        }
        fact.lexical_scopes.reverse();
    }

    fn metadata(
        &mut self,
        declaration: SourceDeclarationId,
        unit: CodeUnit,
        metadata: SignatureMetadata,
    ) {
        self.parsed
            .add_signature_with_source_declaration_metadata(declaration, unit, metadata);
    }

    fn visit_anonymous_class<'tree>(
        &mut self,
        instance: Node<'tree>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let parent = self
            .parsed
            .declarations()
            .iter()
            .filter_map(|candidate| {
                self.parsed
                    .declaration_ranges(candidate)
                    .iter()
                    .filter(|range| {
                        range.start_byte <= instance.start_byte()
                            && instance.end_byte() <= range.end_byte
                    })
                    .map(|range| (range.end_byte - range.start_byte, candidate.clone()))
                    .min()
            })
            .min()
            .map(|(_, candidate)| candidate);
        let package_name = parent
            .as_ref()
            .map(|parent| parent.package_name().to_string())
            .unwrap_or_else(|| self.parsed.package_name.clone());
        let line = instance.start_position().row;
        let column = instance.start_position().column;
        let anonymous_name = format!("anon${line}:{column}");
        let mut fq = child_fq_base(parent.as_ref(), || scala_package_fq(&package_name));
        let (fq_name, segment_kind) = match parent.as_ref() {
            None => (
                scala_root_anonymous_name(self.source, line, column),
                SegmentKind::Type,
            ),
            Some(_) => (anonymous_name, SegmentKind::Nested),
        };
        fq.push(segment_interner().intern(&fq_name, segment_kind));
        let short_name = parent.as_ref().map_or_else(
            || fq_name.clone(),
            |parent| format!("{}$anon${line}:{column}", parent.short_name()),
        );
        let anonymous = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Class,
            package_name.clone(),
            short_name,
            None,
            true,
            fq,
        );
        let declaration = self.declare(&anonymous, instance, None);
        self.parsed
            .add_code_unit(anonymous.clone(), instance, self.source, parent, None);

        let package_prefixes = self
            .package_contexts
            .prefixes_at(instance.start_byte())
            .to_vec();
        let lexical_scopes = scala_lexical_scope_path(instance);
        let mut supertypes = extract_scala_instance_supertypes(instance, self.source);
        for fact in &mut supertypes {
            fact.lookup_path.set_package_prefixes(&package_prefixes);
            fact.lookup_path.set_lexical_scopes(&lexical_scopes);
        }
        if !supertypes.is_empty() {
            self.parsed.set_raw_supertypes(
                anonymous.clone(),
                supertypes.iter().map(|fact| fact.raw.clone()).collect(),
            );
            self.parsed.set_supertype_lookup_paths(
                anonymous.clone(),
                supertypes
                    .iter()
                    .map(|fact| fact.lookup_path.encode())
                    .collect(),
            );
            self.metadata(
                declaration,
                anonymous.clone(),
                SignatureMetadata::new(
                    format!(
                        "new {}",
                        supertypes
                            .iter()
                            .map(|fact| fact.raw.as_str())
                            .collect::<Vec<_>>()
                            .join(" with ")
                    ),
                    Vec::new(),
                )
                .with_recorded_type_parameters(Vec::new())
                .with_class_like_interface(false),
            );
        }

        let Some(body) = scala_anonymous_template_body(instance) else {
            return;
        };
        let mut cursor = body.walk();
        stack.push(ScalaWork::TemplateBody {
            children: body.named_children(&mut cursor).collect(),
            index: 0,
            package_name,
            package_prefixes,
            parent: anonymous,
        });
    }

    fn process_compilation_unit<'tree>(
        &mut self,
        work: ScalaCompilationUnitWork<'tree>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let ScalaCompilationUnitWork {
            children,
            mut index,
            package_name: mut current_package,
            mut package_prefixes,
            mut recovery_owners,
            unmatched_end_names,
        } = work;
        let mut unmatched_end_names = unmatched_end_names.unwrap_or_else(|| {
            let mut unmatched_end_names = HashMap::<String, usize>::default();
            for candidate in &children[index..] {
                if candidate.kind() == "_end_ident" {
                    *unmatched_end_names
                        .entry(scala_node_text(*candidate, self.source).trim().to_string())
                        .or_default() += 1;
                }
            }
            unmatched_end_names
        });
        assert!(
            index < children.len(),
            "scheduled Scala declaration child exists"
        );
        'declaration: {
            let child = children[index];
            index += 1;
            if child.kind() == "_end_ident" {
                let name = scala_node_text(child, self.source).trim();
                if let Some(count) = unmatched_end_names.get_mut(name) {
                    *count -= 1;
                    if *count == 0 {
                        unmatched_end_names.remove(name);
                    }
                }
                if let Some(position) = recovery_owners.iter().rposition(|owner| owner.name == name)
                {
                    recovery_owners.truncate(position);
                }
                break 'declaration;
            }
            if child.is_named() {
                let indentation = child.start_position().column;
                while recovery_owners
                    .last()
                    .is_some_and(|owner| owner.indentation >= indentation)
                {
                    recovery_owners.pop();
                }
                // Every owner still on the stack lexically encloses this
                // child: the indentation rule above is what kept it there.
                // Their own ranges came from the nodes the parse error
                // truncated, so they stop short of what this scope adopts.
                // Grow them with each adopted sibling, or a container ends up
                // not containing its own members (#3291).
                let adopted = node_range(child);
                for owner in &recovery_owners {
                    self.parsed
                        .extend_declaration_range(&owner.declaration, adopted);
                }
            }
            let recovery_parent = recovery_owners
                .last()
                .map(|owner| owner.declaration.clone());
            match child.kind() {
                "package_clause" => {
                    let package = scala_package_name(child, self.source);
                    // Continuation context for content after the clause: when
                    // no package is established yet, a braced clause
                    // establishes the file package (`package com.example { }`
                    // convention — its contents and everything after share
                    // it); once a package is established, a nested braced
                    // clause scopes only its body and the continuation
                    // resumes the outer package (chisel's Aggregate.scala:
                    // `package experimental { }` then top-level `Bundle`,
                    // which stays in the outer package).
                    let outer_package = current_package.clone();
                    let outer_prefixes = package_prefixes.clone();
                    if !package.is_empty() {
                        current_package = if current_package.is_empty() {
                            package
                        } else {
                            format!("{current_package}.{package}")
                        };
                        if self.parsed.package_name.is_empty() {
                            self.parsed.package_name = current_package.clone();
                            self.parsed.content_qualifier = current_package.clone();
                        }
                        package_prefixes.push(current_package.clone());
                    }
                    if let Some(body) = child.child_by_field_name("body") {
                        let (continuation_package, continuation_prefixes) =
                            if outer_package.is_empty() {
                                (current_package.clone(), package_prefixes.clone())
                            } else {
                                (outer_package, outer_prefixes)
                            };
                        stack.push(ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
                            children,
                            index,
                            package_name: continuation_package,
                            package_prefixes: continuation_prefixes,
                            recovery_owners: recovery_owners.clone(),
                            unmatched_end_names: Some(unmatched_end_names),
                        }));
                        stack.push(ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
                            children: scala_compilation_children(body),
                            index: 0,
                            package_name: current_package.clone(),
                            package_prefixes: package_prefixes.clone(),
                            recovery_owners: Vec::new(),
                            unmatched_end_names: None,
                        }));
                        return;
                    }
                }
                "package_object" => {
                    let package = scala_package_name(child, self.source);
                    if package.is_empty() {
                        break 'declaration;
                    }
                    let package_name = if current_package.is_empty() {
                        package
                    } else {
                        format!("{current_package}.{package}")
                    };
                    let mut nested_package_prefixes = package_prefixes.clone();
                    nested_package_prefixes.push(package_name.clone());
                    if self.parsed.package_name.is_empty() {
                        self.parsed.package_name = package_name.clone();
                        self.parsed.content_qualifier = package_name.clone();
                    }
                    if let Some(body) = child.child_by_field_name("body") {
                        stack.push(ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
                            children,
                            index,
                            package_name: current_package,
                            package_prefixes,
                            recovery_owners,
                            unmatched_end_names: Some(unmatched_end_names),
                        }));
                        stack.push(ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
                            children: scala_compilation_children(body),
                            index: 0,
                            package_name,
                            package_prefixes: nested_package_prefixes,
                            recovery_owners: Vec::new(),
                            unmatched_end_names: None,
                        }));
                        return;
                    }
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    let name = scala_type_declaration_name_node(child)
                        .map(|name| scala_node_text(name, self.source).trim().to_string());
                    if let Some(declaration) = self.visit_type_declaration(
                        child,
                        &current_package,
                        &package_prefixes,
                        recovery_parent,
                        stack,
                    ) && let Some(name) = name
                        && unmatched_end_names.contains_key(&name)
                    {
                        recovery_owners.push(ScalaRecoveryOwner {
                            declaration,
                            name,
                            indentation: child.start_position().column,
                        });
                    }
                }
                "function_definition" | "function_declaration" | "given_definition" => {
                    self.visit_function(child, &current_package, recovery_parent.clone())
                }
                "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                    self.visit_field_declaration(child, &current_package, recovery_parent.clone())
                }
                "type_definition" => {
                    self.visit_type_alias(child, &current_package, recovery_parent.clone())
                }
                // Scala 3 puts most `extension` groups at the top level of a
                // file, where they declare package-level methods. Without this
                // arm they were invisible to every declaration consumer.
                "extension_definition" => self.visit_extension_definition(
                    child,
                    &current_package,
                    &package_prefixes,
                    recovery_parent.as_ref(),
                    stack,
                ),
                "ERROR" => {
                    // Tree-sitter can recover a malformed type header as either a definition
                    // inside ERROR or keyword/name/colon children, then emit indented members as
                    // compilation-unit siblings. Preserve the structured owner until its end
                    // marker or a dedent proves the recovery scope has ended.
                    if let Some(type_node) = scala_error_type_declaration(child) {
                        let name = scala_type_declaration_name_node(type_node)
                            .map(|name| scala_node_text(name, self.source).trim().to_string());
                        if let Some(declaration) = self.visit_type_declaration(
                            type_node,
                            &current_package,
                            &package_prefixes,
                            recovery_parent,
                            stack,
                        ) && let Some(name) = name
                        {
                            recovery_owners.push(ScalaRecoveryOwner {
                                declaration,
                                name,
                                indentation: type_node.start_position().column,
                            });
                        }
                    } else if let Some(header) = scala_error_type_header(child)
                        && let Some(declaration) = self.visit_recovered_type_header(
                            child,
                            &header,
                            &current_package,
                            recovery_parent,
                        )
                    {
                        recovery_owners.push(ScalaRecoveryOwner {
                            declaration,
                            name: scala_node_text(header.name, self.source).trim().to_string(),
                            indentation: header.keyword.start_position().column,
                        });
                    }
                }
                _ => {}
            }
        }
        stack.push(ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
            children,
            index,
            package_name: current_package,
            package_prefixes,
            recovery_owners,
            unmatched_end_names: Some(unmatched_end_names),
        }));
    }

    fn visit_recovered_type_header(
        &mut self,
        node: Node<'_>,
        header: &ScalaRecoveredTypeHeader<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) -> Option<CodeUnit> {
        let kind = header.keyword.kind();
        let raw_name = scala_node_text(header.name, self.source).trim();
        if raw_name.is_empty() {
            return None;
        }
        let code_unit = self.scala_type_declaration_unit(
            raw_name,
            package_name,
            parent.as_ref(),
            kind == "object",
        );
        if self.parsed.contains_declaration(&code_unit) {
            return Some(code_unit);
        }
        let occurrence = self.collector.intern_subspan_bytes(
            header.keyword.start_byte(),
            header.colon.end_byte(),
            SourceOccurrenceProvenance::ExplicitSubspan,
        );
        let name = self.collector.intern_node(header.name);
        let declaration = self.collector.declare(occurrence, Some(name));
        self.parsed
            .source_declaration_units
            .push((declaration, code_unit.clone()));
        let mut fact = crate::scala::graph::syntax::scala_declaration_source_fact(
            node,
            self.source,
            declaration,
        );
        self.capture_declaration_context(node, &mut fact);
        self.scala_facts.declarations.push(fact);
        self.captured_declarations.insert(declaration);
        // ERROR can also contain a preceding expression's incomplete tokens.
        // The declaration itself starts at its keyword, not that wrapper.
        // Keep both endpoints on the shared one-based range convention (#3303).
        let opening = node_range(header.keyword);
        let closing = node_range(header.colon);
        self.parsed.add_code_unit_with_range(
            code_unit.clone(),
            Range {
                start_byte: opening.start_byte,
                end_byte: closing.end_byte,
                start_line: opening.start_line,
                end_line: closing.end_line,
            },
            parent,
            None,
        );
        self.parsed
            .add_signature(code_unit.clone(), format!("{kind} {raw_name}"));
        if kind == "trait" {
            self.parsed.set_scala_trait(code_unit.clone());
        }
        Some(code_unit)
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        package_name: &str,
        package_prefixes: &[String],
        parent: Option<CodeUnit>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) -> Option<CodeUnit> {
        let name_node = scala_type_declaration_name_node(node)?;
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return None;
        }

        let code_unit = self.scala_type_declaration_unit(
            raw_name,
            package_name,
            parent.as_ref(),
            node.kind() == "object_definition",
        );
        if self.parsed.contains_declaration(&code_unit) {
            return Some(code_unit);
        }

        let declaration = self.declare(&code_unit, node, Some(name_node));
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
        // A type declaration's own parameter list is what canonical identity
        // reads as generic arity, so a class that writes none records a zero
        // rather than leaving the arity unread (#1651).
        self.metadata(
            declaration,
            code_unit.clone(),
            SignatureMetadata::new(scala_type_signature(node, self.source), Vec::new())
                .with_recorded_type_parameters(scala_declared_type_parameter_names(
                    node,
                    self.source,
                ))
                // Trait-ness is what makes a member found on this template an
                // `implements` edge rather than an `overrides` edge (#1721),
                // and a bounded consumer cannot recover it from the indexed
                // identity: a class, an object and a trait are all
                // `CodeUnitType::Class` rows.
                .with_class_like_interface(node.kind() == "trait_definition"),
        );
        let mut raw_supertypes = Vec::new();
        if let Some(enum_owner) = scala_full_enum_case_owner_supertype(node, self.source) {
            raw_supertypes.push(enum_owner);
        }
        raw_supertypes.extend(extract_scala_supertypes(node, self.source));
        let lexical_scopes = scala_lexical_scope_path(node);
        for fact in &mut raw_supertypes {
            fact.lookup_path.set_package_prefixes(package_prefixes);
            fact.lookup_path.set_lexical_scopes(&lexical_scopes);
        }
        if !raw_supertypes.is_empty() {
            self.parsed.set_raw_supertypes(
                code_unit.clone(),
                raw_supertypes.iter().map(|fact| fact.raw.clone()).collect(),
            );
            self.parsed.set_supertype_lookup_paths(
                code_unit.clone(),
                raw_supertypes
                    .into_iter()
                    .map(|fact| fact.lookup_path.encode())
                    .collect(),
            );
        }
        if node.kind() == "trait_definition" {
            self.parsed.set_scala_trait(code_unit.clone());
        }

        let constructor_modifier =
            crate::scala::graph::syntax::scala_primary_constructor_modifier(node);
        if matches!(node.kind(), "class_definition" | "full_enum_case")
            && (!scala_class_parameter_lists(node).is_empty() || constructor_modifier.is_some())
        {
            let constructor = CodeUnit::with_signature_and_fq(
                self.file.clone(),
                CodeUnitType::Function,
                package_name.to_string(),
                format!("{}.{}", code_unit.short_name(), raw_name),
                Some(scala_method_signature_key(
                    None,
                    &scala_class_parameter_lists(node),
                    None,
                    self.source,
                )),
                false,
                code_unit
                    .fq()
                    .clone()
                    .with_pushed(segment_interner().intern(raw_name, SegmentKind::Member)),
            )
            .with_synthetic(true);
            // Keep the existing constructor identity with parameter lists. An
            // explicit modifier without lists needs its own source anchor too:
            // class and constructor can name different lexical boundaries.
            let anchor = if scala_class_parameter_lists(node).is_empty() {
                constructor_modifier.expect("a constructor without lists has an explicit modifier")
            } else {
                node
            };
            let declaration = self.collector.declare_node(anchor, None);
            assert!(self.captured_declarations.insert(declaration));
            let mut fact = crate::scala::graph::syntax::scala_declaration_source_fact(
                node,
                self.source,
                declaration,
            );
            let visibility =
                constructor_modifier.map_or(DeclaredVisibility::Public, scala_declared_visibility);
            fact.visibility = constructor_modifier
                .map_or(ScalaDeclarationVisibility::Public, |modifier| {
                    crate::scala::graph::syntax::scala_declaration_modifiers(modifier).0
                });
            self.capture_declaration_context(constructor_modifier.unwrap_or(node), &mut fact);
            if constructor_modifier.is_none() {
                fact.access_boundary = None;
            }
            self.scala_facts.declarations.push(fact);
            self.parsed
                .source_declaration_units
                .push((declaration, constructor.clone()));
            self.parsed.add_code_unit(
                constructor.clone(),
                node,
                self.source,
                Some(code_unit.clone()),
                None,
            );
            let signature = scala_primary_constructor_signature(node, self.source);
            self.metadata(
                declaration,
                constructor,
                scala_class_signature_metadata(signature, node, self.source)
                    // The synthetic primary constructor is a constructor, and
                    // saying so is what keeps it out of method families
                    // (#1721) as a proven exclusion rather than as a member
                    // whose modifiers nobody read.
                    .with_callable_modifiers(false, true, visibility)
                    .with_dispatch_extensibility(DispatchExtensibility::Closed),
            );
            self.visit_class_parameter_fields(node, package_name, &code_unit);
        }

        if let Some(body) = node.child_by_field_name("body") {
            let mut cursor = body.walk();
            let mut children = body.named_children(&mut cursor).collect::<Vec<_>>();
            let braced = {
                let mut cursor = body.walk();
                body.children(&mut cursor).any(|child| child.kind() == "{")
            };
            let promoted = (!braced)
                .then(|| {
                    children
                        .iter()
                        .position(|child| {
                            child.start_position().column <= node.start_position().column
                        })
                        .map(|split| children.split_off(split))
                })
                .flatten()
                .unwrap_or_default();
            if !promoted.is_empty() {
                stack.push(ScalaWork::CompilationUnit(ScalaCompilationUnitWork {
                    children: promoted,
                    index: 0,
                    package_name: package_name.to_string(),
                    package_prefixes: package_prefixes.to_vec(),
                    recovery_owners: Vec::new(),
                    unmatched_end_names: None,
                }));
            }
            if !children.is_empty() {
                stack.push(ScalaWork::TemplateBody {
                    children,
                    index: 0,
                    package_name: package_name.to_string(),
                    package_prefixes: package_prefixes.to_vec(),
                    parent: code_unit.clone(),
                });
            }
        }
        Some(code_unit)
    }

    fn visit_class_parameter_fields(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: &CodeUnit,
    ) {
        let is_case_class = node.kind() == "full_enum_case" || scala_structural_is_case_class(node);
        for parameters in scala_class_parameter_lists(node) {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if parameter.kind() != "class_parameter" {
                    continue;
                }
                if !is_case_class && scala_class_parameter_field_keyword(parameter).is_none() {
                    continue;
                }
                let Some(name_node) = parameter.child_by_field_name("name") else {
                    continue;
                };
                let name = scala_node_text(name_node, self.source).trim();
                if name.is_empty() {
                    continue;
                }
                let code_unit = CodeUnit::new_fq(
                    self.file.clone(),
                    CodeUnitType::Field,
                    package_name.to_string(),
                    format!("{}.{}", parent.short_name(), name),
                    parent
                        .fq()
                        .clone()
                        .with_pushed(segment_interner().intern(name, SegmentKind::Member)),
                );
                self.declare(&code_unit, parameter, Some(name_node));
                self.parsed.add_code_unit(
                    code_unit.clone(),
                    parameter,
                    self.source,
                    Some(parent.clone()),
                    None,
                );
                self.parsed.add_signature(
                    code_unit,
                    scala_class_parameter_field_signature(parameter, self.source, name),
                );
            }
        }
    }

    fn process_template_body<'tree>(
        &mut self,
        children: Vec<Node<'tree>>,
        index: usize,
        package_name: &str,
        package_prefixes: &[String],
        parent: &CodeUnit,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        if let Some(child) = children.get(index).copied() {
            stack.push(ScalaWork::TemplateBody {
                children,
                index: index + 1,
                package_name: package_name.to_string(),
                package_prefixes: package_prefixes.to_vec(),
                parent: parent.clone(),
            });
            match child.kind() {
                "function_definition" | "function_declaration" | "given_definition" => {
                    self.visit_function(child, package_name, Some(parent.clone()))
                }
                "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                    self.visit_field_declaration(child, package_name, Some(parent.clone()))
                }
                "type_definition" => {
                    self.visit_type_alias(child, package_name, Some(parent.clone()))
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    self.visit_type_declaration(
                        child,
                        package_name,
                        package_prefixes,
                        Some(parent.clone()),
                        stack,
                    );
                }
                "extension_definition" => self.visit_extension_definition(
                    child,
                    package_name,
                    package_prefixes,
                    Some(parent),
                    stack,
                ),
                "export_declaration" => {
                    if let Some(info) = scala_export_info_from_node(child, self.source) {
                        self.parsed
                            .scala_exports
                            .entry(parent.clone())
                            .or_default()
                            .push(info);
                    }
                }
                "simple_enum_case" => self.visit_enum_case(child, package_name, parent),
                "full_enum_case" => {
                    self.visit_type_declaration(
                        child,
                        package_name,
                        package_prefixes,
                        Some(parent.clone()),
                        stack,
                    );
                }
                "enum_case_definitions" | "enum_body" => {
                    let mut cursor = child.walk();
                    stack.push(ScalaWork::TemplateBody {
                        children: child.named_children(&mut cursor).collect(),
                        index: 0,
                        package_name: package_name.to_string(),
                        package_prefixes: package_prefixes.to_vec(),
                        parent: parent.clone(),
                    });
                }
                _ => {}
            }
        }
    }

    /// An `extension` group's members.
    ///
    /// `parent` is `None` for a group written at the top level of a
    /// compilation unit, which is where Scala 3 code usually puts one; its
    /// methods are then package-level declarations, exactly as the file-graph
    /// walk has always recorded them.
    fn visit_extension_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        package_name: &str,
        package_prefixes: &[String],
        parent: Option<&CodeUnit>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let receiver_parameters = node.child_by_field_name("parameters");
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if self.visit_extension_member(
                child,
                receiver_parameters,
                package_name,
                package_prefixes,
                parent,
                stack,
            ) {
                self.visit_extension_block(
                    child,
                    receiver_parameters,
                    package_name,
                    package_prefixes,
                    parent,
                    stack,
                );
            }
        }
    }

    fn visit_extension_member<'tree>(
        &mut self,
        child: Node<'tree>,
        receiver_parameters: Option<Node<'tree>>,
        package_name: &str,
        package_prefixes: &[String],
        parent: Option<&CodeUnit>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) -> bool {
        match child.kind() {
            "function_definition" | "function_declaration" => {
                self.visit_extension_function(
                    child,
                    receiver_parameters,
                    package_name,
                    parent.cloned(),
                );
            }
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                self.visit_field_declaration(child, package_name, parent.cloned());
            }
            "type_definition" => {
                self.visit_type_alias(child, package_name, parent.cloned());
            }
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                self.visit_type_declaration(
                    child,
                    package_name,
                    package_prefixes,
                    parent.cloned(),
                    stack,
                );
            }
            "template_body" | "block" | "indented_block" => return true,
            _ => {}
        }
        false
    }

    fn visit_extension_block<'tree>(
        &mut self,
        node: Node<'tree>,
        receiver_parameters: Option<Node<'tree>>,
        package_name: &str,
        package_prefixes: &[String],
        parent: Option<&CodeUnit>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let mut pending = vec![node];
        while let Some(node) = pending.pop() {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if self.visit_extension_member(
                    child,
                    receiver_parameters,
                    package_name,
                    package_prefixes,
                    parent,
                    stack,
                ) {
                    pending.push(child);
                }
            }
        }
    }

    fn visit_function(&mut self, node: Node<'_>, package_name: &str, parent: Option<CodeUnit>) {
        self.visit_function_with_signature(node, package_name, parent, None, None);
    }

    fn visit_extension_function(
        &mut self,
        node: Node<'_>,
        receiver_parameters: Option<Node<'_>>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        let receiver_type = scala_extension_receiver_type_node(receiver_parameters);
        self.visit_function_with_signature(
            node,
            package_name,
            parent,
            Some(scala_extension_function_signature(
                node,
                receiver_parameters,
                self.source,
            )),
            receiver_type,
        );
    }

    fn visit_function_with_signature(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
        signature: Option<String>,
        extension_receiver_type: Option<Node<'_>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }

        let effective_name = if raw_name == "this" {
            parent
                .as_ref()
                .map(|code_unit| last_segment(code_unit.short_name()).to_string())
                .unwrap_or_else(|| raw_name.to_string())
        } else {
            raw_name.to_string()
        };
        let short_name = if let Some(parent) = &parent {
            format!("{}.{}", parent.short_name(), effective_name)
        } else {
            effective_name.clone()
        };

        let fq = child_fq_base(parent.as_ref(), || scala_package_fq(package_name))
            .with_pushed(segment_interner().intern(&effective_name, SegmentKind::Member));
        let mut parameter_lists = Vec::new();
        let mut type_parameters = None;
        let mut parameters_cursor = node.walk();
        for child in node.named_children(&mut parameters_cursor) {
            match child.kind() {
                "parameters" => parameter_lists.push(child),
                "type_parameters" => type_parameters = Some(child),
                _ => {}
            }
        }
        let signature_key = scala_method_signature_key(
            type_parameters,
            &parameter_lists,
            extension_receiver_type,
            self.source,
        );
        let code_unit = CodeUnit::with_signature_and_fq(
            self.file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            short_name,
            Some(signature_key),
            false,
            fq,
        );
        let dispatch_extensibility =
            scala_callable_dispatch_extensibility(parent.as_ref(), raw_name);
        let declaration = self.declare(&code_unit, node, Some(name_node));
        // Scala has no `static` keyword: a member of an `object` is the
        // singleton's, and the declaration walk already marks an object by
        // giving its code unit a `$`-suffixed short name, which is the same
        // fact `scala_callable_dispatch_extensibility` reads one line above.
        let owner_is_object = parent
            .as_ref()
            .is_some_and(|owner| owner.short_name().ends_with('$'));
        let is_constructor = raw_name == "this";
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent, None);
        let signature = signature.unwrap_or_else(|| scala_function_signature(node, self.source));
        let metadata =
            scala_function_signature_metadata(signature, node, self.source, dispatch_extensibility)
                .with_callable_modifiers(
                    owner_is_object,
                    is_constructor,
                    scala_declared_visibility(node),
                )
                .with_callable_override_modifier(scala_override_modifier(node))
                .with_extension_receiver_type(extension_receiver_type.map(|receiver_type| {
                    scala_node_text(receiver_type, self.source)
                        .trim()
                        .to_string()
                }))
                .with_extension_receiver_type_identity(extension_receiver_type.and_then(
                    |receiver_type| {
                        scala_structured_type_identity(receiver_type, self.source, node)
                    },
                ));
        self.metadata(declaration, code_unit, metadata);
    }

    fn visit_field_declaration(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        // Definitions bind a pattern; abstract val/var declarations expose
        // one or more name fields instead. Both declare indexed members.
        let names = if let Some(pattern) = node.child_by_field_name("pattern") {
            scala_pattern_names(pattern, self.source)
        } else {
            let mut cursor = node.walk();
            node.children_by_field_name("name", &mut cursor)
                .flat_map(|name| scala_pattern_names(name, self.source))
                .collect()
        };

        for (name, name_node) in names {
            let short_name = if let Some(parent) = &parent {
                format!("{}.{}", parent.short_name(), name)
            } else {
                name.clone()
            };
            let fq = child_fq_base(parent.as_ref(), || scala_package_fq(package_name))
                .with_pushed(segment_interner().intern(&name, SegmentKind::Member));
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                package_name.to_string(),
                short_name,
                fq,
            );
            self.declare(&code_unit, node, Some(name_node));
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
            self.parsed
                .add_signature(code_unit, scala_field_signature(node, self.source, &name));
        }
    }

    fn visit_type_alias(&mut self, node: Node<'_>, package_name: &str, parent: Option<CodeUnit>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = scala_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let code_unit =
            self.scala_type_declaration_unit(name, package_name, parent.as_ref(), false);
        let declaration = self.declare(&code_unit, node, Some(name_node));
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent, None);
        self.metadata(
            declaration,
            code_unit.clone(),
            SignatureMetadata::new(
                scala_node_text(node, self.source).trim().to_string(),
                Vec::new(),
            )
            .with_recorded_type_parameters(scala_declared_type_parameter_names(node, self.source)),
        );
        self.parsed.mark_type_alias(code_unit);
    }

    fn visit_enum_case(&mut self, node: Node<'_>, package_name: &str, parent: &CodeUnit) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = scala_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let code_unit =
            CodeUnit::new_member_field(self.file.clone(), package_name.to_string(), parent, name);
        self.declare(&code_unit, node, Some(name_node));
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed.add_signature(code_unit, format!("case {name}"));
    }
}

fn scala_anonymous_template_body(node: Node<'_>) -> Option<Node<'_>> {
    assert_eq!(node.kind(), "instance_expression");
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "template_body")
}

fn scala_type_declaration_name_node(node: Node<'_>) -> Option<Node<'_>> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(name);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => return Some(child),
            "ERROR" => {
                if let Some(identifier) =
                    first_named_descendant_of_kind_inclusive(child, "identifier")
                {
                    return Some(identifier);
                }
            }
            _ => {}
        }
    }
    None
}

fn scala_error_type_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        )
    })
}

struct ScalaRecoveredTypeHeader<'tree> {
    keyword: Node<'tree>,
    name: Node<'tree>,
    colon: Node<'tree>,
}

fn scala_error_type_header(node: Node<'_>) -> Option<ScalaRecoveredTypeHeader<'_>> {
    let mut keyword = None;
    let mut name = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class" | "object" | "trait" | "enum" => {
                keyword = Some(child);
                name = None;
            }
            "identifier" if keyword.is_some() && name.is_none() => name = Some(child),
            ":" if keyword.is_some() && name.is_some() => {
                let header = ScalaRecoveredTypeHeader {
                    keyword: keyword?,
                    name: name?,
                    colon: child,
                };
                debug_assert!(header.keyword.end_byte() <= header.name.start_byte());
                debug_assert!(header.name.end_byte() <= header.colon.start_byte());
                return Some(header);
            }
            _ => {}
        }
    }
    None
}

fn scala_package_name(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim().to_string())
        .unwrap_or_default()
}

fn scala_type_signature(node: Node<'_>, source: &str) -> String {
    let keyword = match node.kind() {
        "class_definition" => "class",
        "object_definition" => "object",
        "trait_definition" => "trait",
        "enum_definition" => "enum",
        "full_enum_case" => "case",
        _ => "class",
    };
    let name = node
        .child_by_field_name("name")
        .filter(|name| name.parent() == Some(node))
        .or_else(|| scala_type_declaration_name_node(node))
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let type_params = node
        .child_by_field_name("type_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let class_params = scala_class_parameter_lists(node)
        .into_iter()
        .map(|child| scala_node_text(child, source).trim())
        .collect::<String>();
    format!(
        "{}{} {}{}{} {{",
        scala_modifier_prefix(node, source),
        keyword,
        name,
        type_params,
        class_params
    )
}

fn scala_primary_constructor_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .filter(|name| name.parent() == Some(node))
        .or_else(|| scala_type_declaration_name_node(node))
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let params = scala_class_parameter_lists(node)
        .into_iter()
        .map(|child| scala_node_text(child, source).trim())
        .collect::<String>();
    format!("def {name}{params} = {{...}}")
}

fn scala_class_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let parameter_nodes = scala_class_parameter_lists(node);
    if parameter_nodes.is_empty() {
        return SignatureMetadata::new(signature, Vec::new());
    }
    scala_signature_metadata_for_parameter_nodes(signature, &parameter_nodes, source)
}

pub(super) fn scala_class_parameter_lists(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "class_parameters")
        .collect()
}

/// Compact overload-discriminating key stored on Scala function `CodeUnit`s
/// (mirrors `csharp_method_signature_key`): generic arity plus the type text of
/// every value-parameter clause, e.g. `[1](A, B)(C)`. Same-named overloads
/// must be distinct `CodeUnit`s so per-overload maps (ranges, signatures) and
/// per-overload find-usages do not collapse onto the shared fq_name (#1327).
fn scala_method_signature_key(
    type_parameters: Option<Node<'_>>,
    parameter_lists: &[Node<'_>],
    extension_receiver_type: Option<Node<'_>>,
    source: &str,
) -> String {
    let normalize = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut key = String::new();
    if let Some(receiver_type) = extension_receiver_type {
        key.push_str("extension (");
        key.push_str(&normalize(scala_node_text(receiver_type, source)));
        key.push(')');
    }
    let generic_arity = type_parameters.map_or(0, |parameters| parameters.named_child_count());
    if generic_arity > 0 {
        key.push('[');
        key.push_str(&generic_arity.to_string());
        key.push(']');
    }
    for clause in parameter_lists {
        key.push('(');
        let mut cursor = clause.walk();
        let mut first = true;
        for parameter in clause.named_children(&mut cursor) {
            if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                continue;
            }
            if !first {
                key.push_str(", ");
            }
            first = false;
            let text = parameter
                .child_by_field_name("type")
                .map(|type_node| scala_node_text(type_node, source))
                .unwrap_or_else(|| scala_node_text(parameter, source));
            key.push_str(&normalize(text));
        }
        key.push(')');
    }
    key
}

fn scala_function_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let mut parts = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "type_parameters" | "parameters") {
            parts.push(scala_node_text(child, source).trim().to_string());
        }
    }
    let return_type = node
        .child_by_field_name("return_type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();

    format!(
        "{}def {}{}{} = {{...}}",
        scala_modifier_prefix(node, source),
        name,
        parts.join(""),
        return_type
    )
}

fn scala_extension_function_signature(
    node: Node<'_>,
    receiver_parameters: Option<Node<'_>>,
    source: &str,
) -> String {
    let receiver = receiver_parameters
        .map(|parameters| scala_node_text(parameters, source).trim().to_string())
        .unwrap_or_default();
    format!(
        "extension {receiver} {}",
        scala_function_signature(node, source)
    )
}

pub(crate) fn scala_extension_receiver_type_node(
    receiver_parameters: Option<Node<'_>>,
) -> Option<Node<'_>> {
    let receiver_parameters = receiver_parameters?;
    let mut cursor = receiver_parameters.walk();
    let mut receivers = receiver_parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"));
    let receiver = receivers.next()?;
    if receivers.next().is_some() {
        return None;
    }
    receiver.child_by_field_name("type")
}

fn scala_function_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
    dispatch_extensibility: DispatchExtensibility,
) -> SignatureMetadata {
    let mut parameter_nodes = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameters" {
            parameter_nodes.push(child);
        }
    }
    let return_type = node
        .child_by_field_name("return_type")
        .map(|return_type| scala_node_text(return_type, source).trim().to_string());
    let type_parameters = scala_callable_type_parameters(node, source);
    let return_type_identity = node
        .child_by_field_name("return_type")
        .and_then(|return_type| scala_structured_type_identity(return_type, source, node));
    let bare_return_type_parameter = return_type_identity
        .as_ref()
        .and_then(StructuredTypeIdentity::nominal_name)
        .filter(|name| {
            name.path().len() == 1
                && type_parameters
                    .iter()
                    .any(|parameter| parameter == &name.path()[0])
        })
        .map(|name| name.path()[0].clone());
    scala_signature_metadata_for_parameter_nodes(signature, &parameter_nodes, source)
        .with_return_type_text(return_type)
        .with_return_type_identity(return_type_identity)
        .with_type_parameters(type_parameters)
        .with_bare_return_type_parameter(bare_return_type_parameter)
        .with_dispatch_extensibility(dispatch_extensibility)
}

enum ScalaStructuredTypeFrame<'tree> {
    Visit(Node<'tree>),
    Generic { argument_count: usize },
}

/// Preserve the parser-proven nominal shape of a Scala callable return type.
///
/// The flat builder keeps indexing stack-safe for deeply nested generic types.
/// Types whose nominal receiver identity depends on a value path, wildcard,
/// refinement, match, function, tuple or infix interpretation are deliberately
/// left unmodelled so bounded consumers cannot promote them to precision.
fn scala_structured_type_identity(
    node: Node<'_>,
    source: &str,
    callable: Node<'_>,
) -> Option<StructuredTypeIdentity> {
    let lexical_scope = scala_callable_lexical_scope(callable, source)?;
    let mut frames = vec![ScalaStructuredTypeFrame::Visit(node)];
    let mut values = Vec::new();
    let mut builder = StructuredTypeIdentityBuilder::default();

    while let Some(frame) = frames.pop() {
        match frame {
            ScalaStructuredTypeFrame::Visit(current) => match current.kind() {
                "type_identifier" | "stable_type_identifier" => {
                    values.push(builder.named(scala_structured_named_type(
                        current,
                        source,
                        &lexical_scope,
                    )?)?);
                }
                "generic_type" => {
                    let base = current.child_by_field_name("type")?;
                    let arguments = current.child_by_field_name("type_arguments")?;
                    let mut cursor = arguments.walk();
                    let argument_nodes = arguments.named_children(&mut cursor).collect::<Vec<_>>();
                    if argument_nodes.is_empty() {
                        return None;
                    }
                    frames.push(ScalaStructuredTypeFrame::Generic {
                        argument_count: argument_nodes.len(),
                    });
                    frames.extend(
                        argument_nodes
                            .into_iter()
                            .rev()
                            .map(ScalaStructuredTypeFrame::Visit),
                    );
                    frames.push(ScalaStructuredTypeFrame::Visit(base));
                }
                // An annotation does not change the nominal receiver type.
                "annotated_type" => {
                    let mut cursor = current.walk();
                    let mut types = current
                        .named_children(&mut cursor)
                        .filter(|child| child.kind() != "annotation");
                    let base = types.next()?;
                    if types.next().is_some() {
                        return None;
                    }
                    frames.push(ScalaStructuredTypeFrame::Visit(base));
                }
                _ => return None,
            },
            ScalaStructuredTypeFrame::Generic { argument_count } => {
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

fn scala_structured_named_type(
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeName> {
    let mut path = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => {
                let segment = scala_node_text(current, source).trim();
                if segment.is_empty() {
                    return None;
                }
                path.push(segment.to_string());
            }
            "stable_identifier" | "stable_type_identifier" => {
                let mut cursor = current.walk();
                let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
            _ => return None,
        }
    }
    let absolute = path.first().is_some_and(|segment| segment == "_root_");
    if absolute {
        path.remove(0);
    }
    StructuredTypeName::new(path, lexical_scope.to_vec(), absolute)
}

pub fn scala_callable_lexical_scope(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut scope = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "full_enum_case"
        ) {
            let name = ancestor
                .child_by_field_name("name")
                .filter(|name| name.parent() == Some(ancestor))
                .or_else(|| scala_type_declaration_name_node(ancestor))?;
            let name = scala_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            scope.push(if ancestor.kind() == "object_definition" {
                format!("{name}$")
            } else {
                name.to_string()
            });
        }
        current = ancestor.parent();
    }
    scope.reverse();
    Some(scope)
}

fn scala_callable_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let mut parameters = Vec::new();
    let mut current = Some(node);
    while let Some(scope) = current {
        if matches!(
            scope.kind(),
            "function_definition"
                | "function_declaration"
                | "extension_definition"
                | "class_definition"
                | "trait_definition"
                | "enum_definition"
                | "full_enum_case"
        ) {
            let mut cursor = scope.walk();
            for type_parameters in scope
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "type_parameters")
            {
                let mut stack = vec![type_parameters];
                while let Some(current) = stack.pop() {
                    let mut name_cursor = current.walk();
                    for name in current.children_by_field_name("name", &mut name_cursor) {
                        let name = scala_node_text(name, source).trim();
                        if name != "_" && !name.is_empty() {
                            parameters.push(name.to_string());
                        }
                    }
                    let mut child_cursor = current.walk();
                    stack.extend(current.named_children(&mut child_cursor).filter(|child| {
                        matches!(
                            child.kind(),
                            "covariant_type_parameter"
                                | "contravariant_type_parameter"
                                | "type_parameters"
                                | "type_lambda"
                        )
                    }));
                }
            }
        }
        current = scope.parent();
    }
    parameters.sort();
    parameters.dedup();
    parameters
}

fn scala_callable_dispatch_extensibility(
    parent: Option<&CodeUnit>,
    raw_name: &str,
) -> DispatchExtensibility {
    if raw_name == "this"
        || parent.is_none()
        || parent.is_some_and(|owner| owner.short_name().ends_with('$'))
    {
        DispatchExtensibility::Closed
    } else {
        DispatchExtensibility::Open
    }
}

fn scala_signature_metadata_for_parameter_nodes(
    signature: String,
    parameter_nodes: &[Node<'_>],
    source: &str,
) -> SignatureMetadata {
    let parameter_text = parameter_nodes
        .iter()
        .map(|node| scala_node_text(*node, source).trim().to_string())
        .collect::<Vec<_>>()
        .join("");
    if parameter_text.is_empty() {
        return SignatureMetadata::new(signature, Vec::new());
    }
    let parameters = ParameterMetadata::from_signature_labels(
        &signature,
        &parameter_text,
        scala_parameter_label_nodes(parameter_nodes)
            .into_iter()
            .map(|label_node| scala_node_text(label_node, source).trim()),
    );
    let mut metadata = SignatureMetadata::new(signature, parameters)
        .with_callable_parameter_types(scala_parameter_type_spellings(parameter_nodes, source));
    if let Some(arity) = scala_callable_arity(parameter_nodes.first().copied()) {
        metadata = metadata.with_callable_arity(arity);
    }
    metadata
}

/// Each declared parameter's own written type spelling, in declaration order
/// across every parameter list.
///
/// Read from each parameter node's tree-sitter `type` field, never by slicing
/// the rendered signature. A parameter with no `type` field contributes an
/// empty spelling rather than disappearing, because dropping it would shift
/// every later parameter's index.
///
/// Every parameter list is included, not only the first. Recorded arity counts
/// the first list alone (Scala's curried lists each have their own), so the
/// spellings are strictly the more discriminating of the two; method families
/// (#1721) use them only to separate candidates that already agree on name and
/// arity, where more discrimination is never wrong.
///
/// These are spellings, not resolved or erased types: `def run(x: T)` records
/// `T`, whatever `T` turns out to be.
fn scala_parameter_type_spellings(parameter_nodes: &[Node<'_>], source: &str) -> Vec<String> {
    let mut spellings = Vec::new();
    for list in parameter_nodes {
        let mut cursor = list.walk();
        for parameter in list.named_children(&mut cursor) {
            if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                continue;
            }
            spellings.push(
                parameter
                    .child_by_field_name("type")
                    .map(|type_node| scala_node_text(type_node, source).trim().to_string())
                    .unwrap_or_default(),
            );
        }
    }
    spellings
}

/// The declared visibility of one Scala declaration, in the shared vocabulary.
///
/// Keep the coarse private/protected modifier here. An explicit lexical
/// qualifier is recorded separately as a source declaration access boundary;
/// selected access combines that region with this modifier.
fn scala_declared_visibility(node: Node<'_>) -> DeclaredVisibility {
    match crate::scala::graph::syntax::scala_declaration_modifiers(node).0 {
        ScalaDeclarationVisibility::NonApi => DeclaredVisibility::Private,
        ScalaDeclarationVisibility::Protected => DeclaredVisibility::Protected,
        ScalaDeclarationVisibility::Public => DeclaredVisibility::Public,
    }
}

/// Which member of the override-modifier family this Scala declaration writes.
///
/// Scala requires `override` only when redefining a *concrete* member; a
/// member implementing an abstract one legitimately writes nothing. The
/// recorded value is therefore corroborating evidence for a method family
/// (#1721), never the gate that C# and Kotlin make it. `abstract` on a member
/// is Scala's `def` with no body, which the declaration walk does not model
/// here, so only the two written keywords are recorded.
///
/// Read from the declaration's `modifiers` subtree by node kind, never by
/// scanning the rendered signature.
fn scala_override_modifier(node: Node<'_>) -> CallableOverrideModifier {
    let mut cursor = node.walk();
    for modifiers in node.named_children(&mut cursor) {
        if modifiers.kind() != "modifiers" {
            continue;
        }
        // `override` and `abstract` are anonymous tokens of the `modifiers`
        // node in tree-sitter-scala (only `access_modifier`, `open_modifier`
        // and friends are named), and an anonymous token's `kind()` is the
        // literal itself. Matching on `kind()` is therefore reading the tree,
        // not scanning text.
        let mut modifier_cursor = modifiers.walk();
        for modifier in modifiers.children(&mut modifier_cursor) {
            match modifier.kind() {
                "override" => return CallableOverrideModifier::Override,
                "abstract" => return CallableOverrideModifier::Abstract,
                _ => {}
            }
        }
    }
    CallableOverrideModifier::NotDeclared
}

fn scala_callable_arity(parameters: Option<Node<'_>>) -> Option<CallableArity> {
    Some(parameters.map_or(CallableArity::exact(0), callable_arity_for_parameters))
}

fn scala_parameter_label_nodes<'tree>(parameter_nodes: &[Node<'tree>]) -> Vec<Node<'tree>> {
    let mut labels = Vec::new();
    for node in parameter_nodes {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "parameter" | "class_parameter")
                && let Some(name_node) = child.child_by_field_name("name")
            {
                labels.push(name_node);
            }
        }
    }
    labels
}

fn scala_field_signature(node: Node<'_>, source: &str, name: &str) -> String {
    let keyword = if matches!(node.kind(), "var_definition" | "var_declaration") {
        "var"
    } else {
        "val"
    };
    let type_text = node
        .child_by_field_name("type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    let initializer = node
        .child_by_field_name("value")
        .and_then(|value| scala_literal_initializer(value, source, node.start_position().column))
        .map(|value| format!(" = {value}"))
        .unwrap_or_default();

    format!(
        "{}{} {}{}{}",
        scala_modifier_prefix(node, source),
        keyword,
        name,
        type_text,
        initializer
    )
}

fn scala_class_parameter_field_signature(node: Node<'_>, source: &str, name: &str) -> String {
    let keyword = scala_class_parameter_field_keyword(node).unwrap_or("val");
    let type_text = node
        .child_by_field_name("type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    let default_value = node
        .child_by_field_name("default_value")
        .map(|child| format!(" = {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    format!("{keyword} {name}{type_text}{default_value}")
}

pub fn scala_class_parameter_field_keyword(node: Node<'_>) -> Option<&'static str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| match child.kind() {
            "val" => Some("val"),
            "var" => Some("var"),
            _ => None,
        })
}

fn scala_modifier_prefix(node: Node<'_>, source: &str) -> String {
    let mut modifiers = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "modifiers" | "access_modifier" => {
                let text = scala_node_text(child, source).trim();
                if !text.is_empty() {
                    modifiers.push(text.to_string());
                }
            }
            _ => {}
        }
    }

    crate::format_modifier_prefix(modifiers)
}

fn scala_pattern_names<'tree>(node: Node<'tree>, source: &str) -> Vec<(String, Node<'tree>)> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            vec![(scala_node_text(node, source).trim().to_string(), node)]
        }
        "identifiers" => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "operator_identifier") {
                    let text = scala_node_text(child, source).trim();
                    if !text.is_empty() {
                        names.push((text.to_string(), child));
                    }
                }
            }
            names
        }
        _ => {
            let text = scala_pattern_spelling(node, source);
            let text = text.trim();
            if text.is_empty() {
                Vec::new()
            } else {
                vec![(text.to_string(), node)]
            }
        }
    }
}

/// Renders a compound pattern node (tuple, typed, extractor, nested, ...) the
/// same way the pre-existing convention does -- the verbatim source text of
/// the pattern's span -- but with any comments excised. Comments are attached
/// to the tree as `extra` nodes (see tree-sitter-scala's node-types.json) and
/// can appear between any of a pattern's identifiers (e.g.
/// `(left/*: Int*/, right)`), so a plain `source[start..end]` slice of the
/// pattern node would otherwise swallow that comment text verbatim into the
/// emitted binding name. This walks the pattern's own descendants to find
/// every comment node's byte range structurally (via `Node::kind`, not by
/// scanning the text for comment syntax) and copies every other byte of the
/// span unchanged, so a comment-free pattern renders byte-for-byte identical
/// to today's `scala_node_text(node, source).trim()` output.
fn scala_pattern_spelling(node: Node<'_>, source: &str) -> String {
    let mut comment_ranges: Vec<(usize, usize)> = Vec::new();
    let mut cursor = node.walk();
    let mut stack = node.named_children(&mut cursor).collect::<Vec<_>>();
    stack.reverse();
    while let Some(child) = stack.pop() {
        if matches!(child.kind(), "comment" | "line_comment" | "block_comment") {
            comment_ranges.push((child.start_byte(), child.end_byte()));
            continue;
        }
        let mut child_cursor = child.walk();
        let mut grandchildren = child.named_children(&mut child_cursor).collect::<Vec<_>>();
        grandchildren.reverse();
        stack.extend(grandchildren);
    }
    comment_ranges.sort_unstable();

    let start = node.start_byte();
    let end = node.end_byte();
    let mut rendered = String::with_capacity(end - start);
    let mut cursor_byte = start;
    for (comment_start, comment_end) in comment_ranges {
        if comment_start > cursor_byte {
            rendered.push_str(&source[cursor_byte..comment_start]);
        }
        cursor_byte = cursor_byte.max(comment_end);
    }
    if cursor_byte < end {
        rendered.push_str(&source[cursor_byte..end]);
    }
    rendered
}

fn scala_literal_initializer(
    node: Node<'_>,
    source: &str,
    declaration_indent: usize,
) -> Option<String> {
    let kind = node.kind();
    if kind == "string" || crate::is_literal_initializer_kind(kind) {
        let text = scala_node_text(node, source).trim().to_string();
        Some(strip_declaration_indent(&text, declaration_indent))
    } else {
        None
    }
}

pub(super) fn last_segment(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn strip_declaration_indent(text: &str, declaration_indent: usize) -> String {
    let continuation_indent = declaration_indent.saturating_sub(2);
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let mut normalized = vec![first.to_string()];
    for line in lines {
        let trimmed = if line.trim().is_empty() {
            String::new()
        } else {
            line.chars().skip(continuation_indent).collect::<String>()
        };
        normalized.push(trimmed);
    }
    normalized.join("\n")
}

#[cfg(test)]
mod same_package_and_extension_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_test_macros::hardwon;

    fn parse(source: &str) -> ParsedFile {
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "src/Graph.scala",
        );
        let tree = crate::scala::language::parse_tree(source)
            .expect("Scala parser")
            .expect("Scala syntax tree");
        parse_scala_file(&file, source, &tree)
    }

    #[test]
    #[hardwon(
        "d5886539d3ef: quicksilver round 5 on brokk-bifrost-jvm: anonymous templates lost nested definitions"
    )]
    fn anonymous_templates_declare_nested_types_and_extensions() {
        let parsed = parse(
            "package demo\ntrait T\nobject Factory { val t = new T { class Inner { def member = 1 }; object O; trait R; enum E { case A }; extension (x: Int) def f = x } }\n",
        );
        let names = parsed
            .declarations()
            .iter()
            .map(|unit| unit.short_name())
            .collect::<Vec<_>>();
        for name in ["Inner", "member", "O$", "R", "E", "f"] {
            assert!(
                names
                    .iter()
                    .any(|actual| actual.rsplit('.').next() == Some(name)),
                "missing {name}: {names:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#3499: same-file Scala trait inheritance was reported as an unindexed import boundary"
    )]
    fn abstract_and_initialized_fields_keep_all_declared_names() {
        let parsed = parse(
            "package example\ntrait Record {\n  val id: Long\n  var left, right: String\n  val version = 1\n}\n",
        );
        let mut fields = parsed
            .declarations()
            .iter()
            .filter(|unit| unit.is_field())
            .map(|unit| unit.fq_name().to_string())
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(
            fields,
            [
                "example.Record.id",
                "example.Record.left",
                "example.Record.right",
                "example.Record.version",
            ]
        );
    }
    /// Scala 3 writes most `extension` groups at the top level of a file, where
    /// their members are package-level declarations. The walk used to handle
    /// `extension` only inside a template body, so such a file declared nothing.
    #[test]
    #[hardwon(
        "e6ff10dcd268: Scala 3 top-level extension methods must be declared at package scope"
    )]
    fn top_level_extension_members_are_package_level_declarations() {
        let parsed =
            parse("package example\n\nextension (s: String)\n  def asInt: Int = s.toInt\n");

        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.fq_name() == "example.asInt" && unit.is_function()),
            "top-level extension methods must be declared: {:?}",
            parsed.declarations()
        );
    }
    #[test]
    fn canonical_walk_shares_declaration_roles_and_captures_source_only_locals() {
        let source = "package demo\nimport lib.{Widget as Renamed, Tools}\ncase class Box(value: Int) { def run(x: Int): Box = { val local: Box = this; helper(x); local } }\nobject Registry { def instance: Registry.type = this }\n";
        let parsed = parse(source);
        let canonical = parsed.source_facts.as_ref().expect("Scala canonical facts");
        let scala = canonical
            .scala
            .as_ref()
            .expect("Scala declaration properties");
        assert!(scala.valid_links(&canonical.occurrences));
        assert!(
            scala
                .declarations
                .iter()
                .filter_map(|fact| fact.callable.as_ref())
                .any(|callable| callable.return_type_is_singleton
                    && callable
                        .return_type_expression
                        .as_ref()
                        .is_some_and(|expression| { expression.segments == ["Registry"] }))
        );
        for (declaration, unit) in &parsed.source_declaration_units {
            let declaration = canonical.occurrences.declaration(*declaration);
            if unit.is_function() && !unit.is_synthetic() {
                let structural = canonical
                    .structural
                    .nodes()
                    .iter()
                    .find(|node| node.occurrence == declaration.occurrence)
                    .expect("declared function shares its structural occurrence");
                assert_eq!(structural.name, declaration.name);
            }
        }
        assert!(canonical.structural.nodes().iter().any(|node| node.kind
            == brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Call));
        assert!(scala.declarations.iter().any(|fact| {
            let declaration = canonical.occurrences.declaration(fact.declaration);
            declaration.name.is_some_and(|name| {
                let range = canonical.occurrences.occurrence(name).range;
                &source[range.start_byte..range.end_byte] == "local"
            }) && !parsed
                .source_declaration_units
                .iter()
                .any(|(id, _)| *id == fact.declaration)
        }));
        assert_eq!(parsed.imports.len(), 2);
        for (id, import) in canonical.generic_imports.iter().zip(&parsed.imports) {
            assert_eq!(
                *import,
                canonical.imports[id.index()].import_info(&canonical.occurrences)
            );
        }
        let alias = canonical.imports[0]
            .alias_occurrence
            .expect("renamed token");
        let range = canonical.occurrences.occurrence(alias).range;
        assert_eq!(&source[range.start_byte..range.end_byte], "Renamed");
        assert!(
            canonical
                .structural
                .nodes()
                .iter()
                .any(|node| node.occurrence == alias)
        );
    }
    #[test]
    #[hardwon(
        "513bb1fcc038: a class and its synthetic constructor shared one source declaration, so the selected unit read and the Java inheritance read rejected the class (Scala precedence census G4)"
    )]
    fn a_class_and_its_synthetic_constructor_are_distinct_source_declarations() {
        let parsed = parse("package app\nclass Elem(val value: Int)\nobject Elem\n");
        let declarations_of = |short_name: &str| {
            parsed
                .source_declaration_units
                .iter()
                .filter(|(_, unit)| unit.short_name() == short_name)
                .map(|(declaration, _)| *declaration)
                .collect::<Vec<_>>()
        };
        let class = declarations_of("Elem");
        let constructor = declarations_of("Elem.Elem");
        assert_eq!(class.len(), 1, "{:?}", parsed.source_declaration_units);
        assert_eq!(
            constructor.len(),
            1,
            "{:?}",
            parsed.source_declaration_units
        );
        assert_ne!(class, constructor);
    }
    #[test]
    fn canonical_walk_preserves_anonymous_member_owners_and_enum_constructors() {
        let parsed = parse(
            "enum Shape { case Circle(radius: Int) }\nclass Factory { def make = new Runnable { def run(): Unit = () } }\n",
        );
        let canonical = parsed.source_facts.as_ref().expect("Scala canonical facts");
        let scala = canonical
            .scala
            .as_ref()
            .expect("Scala declaration properties");
        assert!(scala.valid_links(&canonical.occurrences));
        assert!(
            scala
                .declarations
                .iter()
                .any(|fact| fact.is_full_enum_case && fact.is_case_class)
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .any(|unit| unit.short_name().contains("anon$") && unit.is_function())
        );
        assert!(parsed.declarations().iter().all(|unit| {
            parsed
                .source_declaration_units
                .iter()
                .any(|(_, linked)| linked == unit)
        }));
    }
    /// Grammar-boundary contract: the final named child of a postfix application
    /// is its operator; symbolic import paths and generic annotation names are
    /// nodes, too. Extension groups are transparent members inside templates.
    #[test]
    fn scala_structural_grammar_fields() {
        use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind as K, Role};
        let source = "import +.Item\nimport holder.+\n@Ann[Int] class Tagged\ntrait Host { extension (s: String) { def member = s } }\nextension (s: String) { def top = s }\ndef run(rows: List[Int]) = { rows toList; (rows) toList; rows.size }\n";
        let tree = crate::scala::language::parse_tree(source).unwrap().unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().unwrap();
        let text = |id| {
            let range = facts.occurrences.occurrence(id).range;
            &source[range.start_byte..range.end_byte]
        };
        let mut stack = vec![tree.root_node()];
        let mut checked = Vec::new();
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            let expected = match node.kind() {
                "postfix_expression" => {
                    let operator = node.named_child(node.named_child_count() - 1).unwrap();
                    assert_eq!(operator.kind(), "identifier");
                    assert_eq!(scala_node_text(operator, source), "toList");
                    Some((K::Call, Some(operator)))
                }
                "annotation" => {
                    let name = node.child_by_field_name("name").unwrap();
                    assert_eq!(name.kind(), "generic_type");
                    Some((K::Decorator, Some(name)))
                }
                "function_definition" => {
                    let name = node.child_by_field_name("name").unwrap();
                    match scala_node_text(name, source) {
                        "member" => Some((K::Method, Some(name))),
                        "top" => Some((K::Function, Some(name))),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some((kind, name)) = expected {
                let fact = facts
                    .structural
                    .nodes()
                    .iter()
                    .find(|fact| {
                        facts.occurrences.occurrence(fact.occurrence).range == node_range(node)
                            && fact.kind == kind
                    })
                    .unwrap_or_else(|| panic!("missing {kind:?}: {}", node.to_sexp()));
                assert_eq!(
                    fact.name.map(text),
                    name.map(|name| scala_node_text(name, source))
                );
                checked.push(kind);
            }
        }
        assert_eq!(checked.len(), 5, "{checked:?}");
        let imports = facts
            .structural
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| node.kind == K::Import)
            .map(|(id, _)| {
                facts
                    .structural
                    .roles(u32::try_from(id).unwrap())
                    .iter()
                    .filter(|role| role.role == Role::Module)
                    .map(|role| text(role.name.expect("module path name")))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(imports, [vec!["Item", "+.Item"], vec!["+", "holder.+"]]);
    }

    /// Preserve slots when the released grammar accepts an unfinished
    /// constructor parameter without a type field. No inferred type is claimed.
    #[test]
    fn scala_constructor_type_fields_match_grammar_slots() {
        for (source, expected) in [
            (
                "class Incomplete(first, second: String)",
                vec!["", "String"],
            ),
            (
                "class Typed(first: Any, second: String)",
                vec!["Any", "String"],
            ),
            (
                "class Curried(first: Int)(second: String)",
                vec!["Int", "String"],
            ),
        ] {
            let tree = crate::scala::language::parse_tree(source).unwrap().unwrap();
            let class = tree.root_node().named_child(0).unwrap();
            assert_eq!(class.kind(), "class_definition");
            let mut cursor = class.walk();
            let lists = class
                .children_by_field_name("class_parameters", &mut cursor)
                .collect::<Vec<_>>();
            let grammar_types = lists
                .iter()
                .flat_map(|list| {
                    let mut cursor = list.walk();
                    list.named_children(&mut cursor)
                        .filter(|node| node.kind() == "class_parameter")
                        .map(|node| {
                            node.child_by_field_name("type")
                                .map(|node| scala_node_text(node, source))
                                .unwrap_or("")
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            assert_eq!(grammar_types, expected);
            let parsed = parse(source);
            let metadata = parsed
                .signature_metadata
                .iter()
                .filter(|(_, metadata)| {
                    metadata
                        .iter()
                        .any(|metadata| metadata.callable_is_constructor())
                })
                .flat_map(|(_, metadata)| metadata)
                .find_map(|metadata| metadata.callable_parameter_types())
                .unwrap();
            assert_eq!(metadata, grammar_types, "{source}");
        }
    }

    /// Imports in distinct extension groups have distinct source regions even
    /// when their tokens are identical. Compare stored facts with AST ancestry.
    #[test]
    fn scala_extension_import_scopes_match_grammar_ancestors() {
        let source = "import root.One\ntrait Host {\n  extension (s: String) { def first = { import local.One; s } }\n  extension (i: Int) { def second = { import local.One; i } }\n}\n";
        let tree = crate::scala::language::parse_tree(source).unwrap().unwrap();
        assert!(!tree.root_node().has_error());
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().unwrap();
        let mut stack = vec![tree.root_node()];
        let mut checked = 0;
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            if node.kind() != "import_declaration" {
                continue;
            }
            let import = facts
                .imports
                .iter()
                .find(|import| {
                    facts.occurrences.occurrence(import.declaration).range == node_range(node)
                })
                .unwrap();
            let actual = import
                .path
                .as_ref()
                .unwrap()
                .lexical_scopes
                .iter()
                .map(|id| facts.occurrences.occurrence(*id).range)
                .collect::<Vec<_>>();
            let mut parent = node.parent();
            let mut expected = Vec::new();
            let mut extensions = 0;
            while let Some(node) = parent {
                if matches!(
                    node.kind(),
                    "template_body"
                        | "trait_definition"
                        | "extension_definition"
                        | "function_definition"
                        | "block"
                ) {
                    expected.push(node_range(node));
                }
                extensions += usize::from(node.kind() == "extension_definition");
                parent = node.parent();
            }
            expected.reverse();
            assert_eq!(actual, expected, "{}", node.to_sexp());
            checked += extensions;
        }
        assert_eq!(checked, 2);
    }
    /// On unfinished input the grammar can expose a raw keyword/name/colon
    /// header in ERROR. Preserve that keyword rather than guessing class.
    #[test]
    #[hardwon("d5886539d3ef: recovered type header ranges included the preceding assignment")]
    fn scala_recovered_header_kind_matches_grammar_keyword() {
        // The released grammar retains the name in these raw ERROR headers.
        // Its corresponding object recovery drops the name, so that shape is
        // correctly declined rather than reconstructed from source text.
        for keyword in ["class", "trait", "enum"] {
            let source =
                format!("package demo\ndef helper =\n{keyword} Broken:\n  val value: Int =\n");
            let tree = crate::scala::language::parse_tree(&source)
                .unwrap()
                .unwrap();
            let mut cursor = tree.root_node().walk();
            let error = tree
                .root_node()
                .named_children(&mut cursor)
                .find(|node| node.kind() == "ERROR")
                .unwrap();
            let mut cursor = error.walk();
            let token = error
                .children(&mut cursor)
                .find(|node| node.kind() == keyword)
                .unwrap();
            assert!(!token.is_named());
            let header = scala_error_type_header(error).unwrap();
            assert_eq!(header.keyword, token);
            assert_eq!(header.name.kind(), "identifier");
            assert_eq!(scala_node_text(header.name, &source), "Broken");
            assert_eq!(header.colon.kind(), ":");

            let parsed = parse(&source);
            let facts = parsed.source_facts.as_ref().unwrap();
            let (declaration, unit) = parsed
                .source_declaration_units
                .iter()
                .find(|(id, _)| {
                    facts.occurrences.declaration(*id).name.is_some_and(|name| {
                        facts.occurrences.occurrence(name).range == node_range(header.name)
                    })
                })
                .unwrap();
            let occurrence = facts
                .occurrences
                .occurrence(facts.occurrences.declaration(*declaration).occurrence);
            let expected = Range {
                start_byte: header.keyword.start_byte(),
                end_byte: header.colon.end_byte(),
                start_line: 3,
                end_line: 3,
            };
            assert_eq!(
                occurrence.provenance,
                SourceOccurrenceProvenance::ExplicitSubspan
            );
            assert_eq!(occurrence.range, expected, "{keyword}");
            assert_eq!(parsed.declaration_ranges(unit), [expected], "{keyword}");
        }
    }
}
