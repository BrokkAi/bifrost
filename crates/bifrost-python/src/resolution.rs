//! File-local lexical identity production. Runtime observation selection remains
//! separate: a known binding slot is not proof of an initialized value.

use crate::bindings::{
    PythonLexicalScopeInventory, collect_binding_targets, is_comprehension,
    python_type_parameter_binder_node, python_type_parameters,
};
use crate::syntax::{
    python_keyword_argument_label, python_node_is_in_annotation, python_parameter_node,
};
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::DeclarationKind;
use brokk_bifrost_core::analyzer::resolution_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
use brokk_bifrost_core::analyzer::tree_walk::{find_ancestor, is_field_child, named_children_iter};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

mod exports;
mod guards;
mod imports;
mod temporal;
mod typed;

fn future_annotations_enabled(nodes: &[Node<'_>], source: &str) -> bool {
    nodes
        .iter()
        .filter(|node| node.kind() == "future_import_statement")
        .any(|node| {
            let mut cursor = node.walk();
            node.children_by_field_name("name", &mut cursor)
                .any(|name| {
                    let imported = if name.kind() == "aliased_import" {
                        name.child_by_field_name("name")
                            .expect("future import name")
                    } else {
                        name
                    };
                    &source[imported.byte_range()] == "annotations"
                })
        })
}

struct Scope<'tree> {
    node: Node<'tree>,
    globals: HashSet<String>,
    nonlocals: HashSet<String>,
    bindings: Vec<Node<'tree>>,
}

struct Producer<'source, 'collector> {
    source: &'source str,
    collector: &'collector mut PrimarySourceFactCollector<'source>,
    facts: FileResolutionFacts,
    occurrences: Vec<SourceOccurrenceId>,
    declarations: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    names: HashMap<String, ResolutionNameId>,
    node_guards: HashMap<usize, u32>,
    iteration_guards: HashMap<usize, u32>,
}

impl Producer<'_, '_> {
    fn scope<'tree>(
        &mut self,
        scopes: &mut Vec<Scope<'tree>>,
        node: Node<'tree>,
        parent: Option<ResolutionScopeId>,
        kind: ResolutionScopeKind,
    ) -> ResolutionScopeId {
        let id = ResolutionScopeId::new(dense_ordinal(scopes.len(), "Python scopes"));
        self.facts.scopes.push(ResolutionScopeFact {
            id,
            parent,
            owner: None,
            kind,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        });
        scopes.push(Scope {
            node,
            globals: HashSet::default(),
            nonlocals: HashSet::default(),
            bindings: Vec::new(),
        });
        id
    }

    fn site(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        kind: ResolutionSiteKind,
    ) -> ResolutionSiteId {
        let id = self
            .facts
            .add_site(scope, kind, node.start_byte(), node.end_byte());
        self.occurrences.push(self.collector.intern_node(node));
        if let Some(&guard) = self.node_guards.get(&node.id()) {
            self.facts
                .python_site_guards
                .push(PythonNativeSiteGuardFact { site: id, guard });
        }
        id
    }

    fn identifier(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        kind: ResolutionSiteKind,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        let site = self.site(node, scope, kind);
        let name = self.semantic_name(node);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role,
            namespace,
            qualifier: None,
        });
        site
    }

    /// An identifier's semantic name: Python's class-private names are
    /// compiler-mangled (`__x` in class `C` is `_C__x`); the independent source
    /// occurrence/declaration bridge retains the original public spelling.
    /// Header expressions execute outside the class body being defined.
    fn semantic_name(&mut self, node: Node<'_>) -> ResolutionNameId {
        let text = &self.source[node.byte_range()];
        let lookup = if text.starts_with("__") && !text.ends_with("__") && !text.contains('.') {
            find_ancestor(node, |class| {
                class.kind() == "class_definition"
                    && class.child_by_field_name("body").is_some_and(|body| {
                        body.start_byte() <= node.start_byte() && node.end_byte() <= body.end_byte()
                    })
            })
            .and_then(|class| class.child_by_field_name("name"))
            .map(|class| self.source[class.byte_range()].trim_start_matches('_'))
            .filter(|class| !class.is_empty())
            .map_or_else(|| text.to_owned(), |class| format!("_{class}{text}"))
        } else {
            text.to_owned()
        };
        self.facts.intern_name(&mut self.names, &lookup)
    }

    fn omitted_reference(&mut self, node: Node<'_>, scope: ResolutionScopeId) {
        let site = self.site(node, scope, ResolutionSiteKind::UnsupportedRoute);
        self.facts.add_route_gap(
            site,
            ResolutionRouteGap::OmittedReference {
                scope,
                terminal: None,
                namespace: None,
            },
        );
    }

    fn gap(&mut self, node: Node<'_>, scope: ResolutionScopeId, kind: ResolutionGapKind) {
        let site = self.site(node, scope, ResolutionSiteKind::UnsupportedExpression);
        self.facts.gaps.push(ResolutionGapFact::new(site, kind));
    }
}

/// Produce alongside the structural walk, sharing the exact source occurrence
/// collector. All temporary maps are dropped with this one parse operation.
pub(super) fn produce<'source, 'unit>(
    root: Node<'_>,
    source: &'source str,
    collector: &mut PrimarySourceFactCollector<'source>,
    units: impl Iterator<Item = &'unit (SourceDeclarationId, CodeUnit)>,
    receiver_fields: &HashMap<CodeUnit, (SourceDeclarationId, CodeUnit)>,
) -> (
    FileResolutionFacts,
    Vec<SourceOccurrenceId>,
    Vec<(ResolutionSiteId, SourceDeclarationId)>,
) {
    let mut p = Producer {
        source,
        collector,
        facts: FileResolutionFacts::default(),
        occurrences: Vec::new(),
        declarations: Vec::new(),
        names: HashMap::default(),
        node_guards: HashMap::default(),
        iteration_guards: HashMap::default(),
    };
    let units = units
        .map(|(declaration, unit)| (*declaration, unit))
        .collect::<HashMap<_, _>>();
    let mut scopes = Vec::<Scope<'_>>::new();
    let mut scope_by_node = HashMap::default();
    let mut node_scopes = HashMap::default();
    let mut parameters = HashMap::default();
    let mut generic_bindings = Vec::new();
    let mut generic_annotation_scopes = HashMap::default();
    let mut generic_runtime_scopes = HashSet::default();
    let mut binding_tokens = HashSet::default();
    let mut formal_lists = HashSet::default();
    let mut pending = vec![(root, None, None, None)];
    let mut node_guards = HashMap::default();
    let mut iterable_scopes = HashMap::default();
    let mut nodes = Vec::new();
    // Scope creation and evaluation routing are independent of slot allocation.
    while let Some((node, containing, evaluating, guard)) = pending.pop() {
        if node.is_missing() {
            continue;
        }
        let evaluating = iterable_scopes.get(&node.id()).copied().or(evaluating);
        let mut body_parent = containing;
        let mut body_evaluation = evaluating;
        // Annotation evaluation can see class locals. Runtime bodies use a
        // parallel lexical continuation with aliases to the same formals, so
        // skipping a class never discards its captured generic parameters.
        if let Some(formals) = python_type_parameters(node) {
            let annotation = p.scope(&mut scopes, node, evaluating, ResolutionScopeKind::Block);
            let runtime_parent = find_scope_in_chain(
                evaluating,
                |id| p.facts.scopes[id.index()].parent,
                |id| p.facts.scopes[id.index()].kind != ResolutionScopeKind::TypeBody,
            );
            let runtime = p.scope(&mut scopes, node, evaluating, ResolutionScopeKind::Block);
            generic_annotation_scopes.insert(annotation, runtime);
            generic_runtime_scopes.insert(runtime);
            if runtime_parent != evaluating {
                p.facts
                    .scope_continuations
                    .push(ResolutionScopeContinuationFact {
                        scope: runtime,
                        parent: runtime_parent,
                    });
            }
            scopes[annotation.index()].node = formals;
            scopes[runtime.index()].node = formals;
            formal_lists.insert(formals.id());
            iterable_scopes.insert(formals.id(), annotation);
            let mut formal_names = HashSet::default();
            for formal in named_children_iter(formals).filter(|formal| !formal.is_extra()) {
                if let Some(token) = python_type_parameter_binder_node(formal) {
                    binding_tokens.insert(token.id());
                    if !formal_names.insert(&source[token.byte_range()]) {
                        p.gap(token, annotation, ResolutionGapKind::MalformedSyntax);
                        continue;
                    }
                    generic_bindings.push((token, annotation, runtime));
                } else {
                    p.gap(formal, annotation, ResolutionGapKind::MalformedSyntax);
                }
            }
            if let Some(params) = node.child_by_field_name("parameters") {
                for param in named_children_iter(params) {
                    if let Some(annotation_node) = param.child_by_field_name("type") {
                        iterable_scopes.insert(annotation_node.id(), annotation);
                    }
                }
            }
            for field in ["return_type", "superclasses", "right"] {
                if let Some(expression) = node.child_by_field_name(field) {
                    iterable_scopes.insert(expression.id(), annotation);
                }
            }
            body_parent = Some(runtime);
            body_evaluation = Some(runtime);
        } else if node.kind() == "type_alias_statement" {
            // Even a non-generic alias RHS is an annotation evaluation scope.
            let annotation = p.scope(&mut scopes, node, evaluating, ResolutionScopeKind::Block);
            if let Some(rhs) = node.child_by_field_name("right") {
                iterable_scopes.insert(rhs.id(), annotation);
            }
        }
        let creates = containing.is_none()
            || matches!(
                node.kind(),
                "class_definition" | "function_definition" | "lambda"
            )
            || is_comprehension(node.kind());
        let mut body_scope = evaluating;
        let mut child_containment = containing;
        if creates {
            // A recovered file can have an ERROR root rather than a module.
            // File identity determines its module scope, independent of grammar recovery.
            let kind = if containing.is_none() {
                ResolutionScopeKind::CompilationUnit
            } else if node.kind() == "class_definition" {
                ResolutionScopeKind::TypeBody
            } else {
                ResolutionScopeKind::Executable
            };
            let id = p.scope(&mut scopes, node, body_parent, kind);
            let continuation = find_scope_in_chain(
                body_evaluation,
                |id| p.facts.scopes[id.index()].parent,
                |id| p.facts.scopes[id.index()].kind != ResolutionScopeKind::TypeBody,
            );
            if continuation != body_parent {
                p.facts
                    .scope_continuations
                    .push(ResolutionScopeContinuationFact {
                        scope: id,
                        parent: continuation,
                    });
            }
            scope_by_node.insert(node.id(), id);
            body_scope = Some(id);
            child_containment = Some(id);
            if let Some(params) = node.child_by_field_name("parameters") {
                for param in named_children_iter(params) {
                    if let Some(cursor) = python_parameter_node(param) {
                        parameters.insert(cursor.id(), id);
                        scopes[id.index()].bindings.push(cursor);
                    }
                }
            }
        }
        let current = evaluating.unwrap_or_else(|| body_scope.expect("root scope"));
        node_scopes.insert(node.id(), current);
        nodes.push(node);
        if let Some(guard) = guard {
            node_guards.insert(node.id(), guard);
        }
        let guard_scope = if is_comprehension(node.kind()) {
            body_scope.expect("comprehension execution scope")
        } else {
            current
        };
        let child_guards = guards::child_guards(&mut p, node, guard_scope, guard);
        let children = named_children_iter(node).collect::<Vec<_>>();
        if is_comprehension(node.kind())
            && let Some(first) = children
                .iter()
                .find(|child| child.kind() == "for_in_clause")
        {
            let mut cursor = first.walk();
            for iterable in first.children_by_field_name("right", &mut cursor) {
                iterable_scopes.insert(iterable.id(), current);
            }
        }
        for child in children.into_iter().rev() {
            let scope = if node == root
                || is_comprehension(node.kind())
                || is_field_child(node, child, "body")
            {
                body_scope
            } else {
                Some(current)
            };
            let child_guard = if matches!(node.kind(), "function_definition" | "lambda")
                && is_field_child(node, child, "body")
            {
                None
            } else {
                child_guards.get(&child.id()).copied().or(guard)
            };
            pending.push((child, child_containment, scope, child_guard));
        }
    }
    // A callable's availability guard does not guard its parameter bindings:
    // they are initialized whenever that callable is entered. Annotation and
    // default expressions keep their definition-time guards.
    node_guards.retain(|node, _| !parameters.contains_key(node));
    p.node_guards = node_guards;
    for (index, scope) in scopes.iter_mut().enumerate() {
        if p.facts.scopes[index].kind == ResolutionScopeKind::Block {
            continue;
        }
        let node = scope.node;
        if is_comprehension(node.kind()) {
            for clause in named_children_iter(node).filter(|child| child.kind() == "for_in_clause")
            {
                if let Some(target) = clause.child_by_field_name("left") {
                    collect_binding_targets(target, source, &mut || true, |_, token| {
                        scope.bindings.push(token)
                    })
                    .expect("unbounded target collection");
                }
            }
        } else {
            let parameter_names = scope
                .bindings
                .iter()
                .map(|token| source[token.byte_range()].to_owned())
                .collect::<Vec<_>>();
            let inventory =
                PythonLexicalScopeInventory::collect_bounded(node, source, parameter_names, || {
                    true
                })
                .expect("unbounded inventory");
            scope.globals = inventory.global_names().map(str::to_owned).collect();
            scope.nonlocals = inventory.nonlocal_names().map(str::to_owned).collect();
            scope.bindings.extend(inventory.binding_nodes());
        }
    }
    // Slots are allocated after the entire function/module inventories exist.
    // Nonlocal aliases can therefore target a later enclosing write.
    let mut slots = HashMap::<(ResolutionScopeId, String), ResolutionSiteId>::default();
    let mut events = Vec::new();
    let mut deferred = Vec::new();
    for (scope_index, scope_data) in scopes.iter().enumerate() {
        let scope = ResolutionScopeId::new(dense_ordinal(scope_index, "Python scope"));
        for &token in &scope_data.bindings {
            if !binding_tokens.insert(token.id()) {
                continue;
            }
            let name = source[token.byte_range()].to_owned();
            let operation = binding_operation(token).1;
            if operation.kind() == "named_expression" && invalid_walrus(operation, &name, source) {
                p.gap(
                    token,
                    node_scopes[&token.id()],
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                );
                continue;
            }
            if scope_data.nonlocals.contains(&name) {
                deferred.push((scope, token, name));
                continue;
            }
            let target_scope = if scope_data.globals.contains(&name) {
                ResolutionScopeId::new(0)
            } else {
                scope
            };
            let slot = *slots
                .entry((target_scope, name))
                .or_insert_with(|| make_slot(&mut p, token, target_scope));
            events.push((scope, token, slot));
        }
    }
    for (scope, token, name) in deferred {
        let target = find_scope_in_chain(
            p.facts.scopes[scope.index()].parent,
            |id| p.facts.scopes[id.index()].parent,
            |id| {
                matches!(
                    scopes[id.index()].node.kind(),
                    "function_definition" | "lambda"
                ) && slots.contains_key(&(id, name.clone()))
            },
        );
        if let Some(target) = target {
            events.push((scope, token, slots[&(target, name)]));
        } else {
            p.gap(token, scope, ResolutionGapKind::UnsupportedScopeOrBinder);
        }
    }
    let continuations = p
        .facts
        .scope_continuations
        .iter()
        .map(|row| (row.scope, row.parent))
        .collect::<HashMap<_, _>>();
    let parents = p
        .facts
        .scopes
        .iter()
        .map(|scope| (scope.id, scope.parent))
        .collect::<HashMap<_, _>>();
    let mut redirected = HashSet::default();
    let mut event_by_token = HashMap::default();
    for (scope, token, slot) in events {
        let execution_scope = parameters
            .get(&token.id())
            .copied()
            .unwrap_or(node_scopes[&token.id()]);
        // A walrus's inventory scope can surround its execution comprehension.
        let slot_scope = p.facts.sites[slot.index()].scope;
        if execution_scope != slot_scope {
            find_scope_in_chain(
                Some(execution_scope),
                |id| continuations.get(&id).copied().unwrap_or(parents[&id]),
                |id| {
                    if id == slot_scope {
                        return true;
                    }
                    if (id == execution_scope || is_comprehension(scopes[id.index()].node.kind()))
                        && redirected.insert((id, slot))
                    {
                        alias(&mut p, token, id, slot);
                    }
                    false
                },
            );
        }
        let target = p.identifier(
            token,
            execution_scope,
            ResolutionSiteKind::ValueReference,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let (kind, operation) = binding_operation(token);
        let authored = match kind {
            ResolutionBindingEventKind::Function | ResolutionBindingEventKind::Class => {
                let namespace = if kind == ResolutionBindingEventKind::Class {
                    ResolutionNamespace::Type
                } else {
                    ResolutionNamespace::Callable
                };
                let site_kind = if kind == ResolutionBindingEventKind::Class {
                    ResolutionSiteKind::TypeDeclaration
                } else {
                    ResolutionSiteKind::CallableDeclaration
                };
                let authored = p.identifier(
                    token,
                    scope,
                    site_kind,
                    ResolutionIdentifierRole::Declaration,
                    namespace,
                );
                if kind == ResolutionBindingEventKind::Function {
                    // Authored identity is retained before typed parameter/result
                    // production. An incomplete header is not a zero-arity proof.
                    p.facts
                        .callable_signatures
                        .push(ResolutionCallableSignatureFact {
                            callable: authored,
                            type_parameter_count: 0,
                            result_types: Vec::new(),
                        });
                    p.facts
                        .add_gap(authored, ResolutionGapKind::UnsupportedCallApplicability);
                }
                let declaration_node = operation
                    .parent()
                    .filter(|parent| parent.kind() == "decorated_definition")
                    .unwrap_or(operation);
                let declaration = p.collector.declare_node(declaration_node, Some(token));
                p.declarations.push((authored, declaration));
                if let Some(unit) = units.get(&declaration) {
                    p.facts.definition_units.push(ResolutionDefinitionUnitFact {
                        declaration: authored,
                        unit: (*unit).clone(),
                    });
                } else {
                    if kind == ResolutionBindingEventKind::Function {
                        p.collector
                            .mark_lexical(declaration, DeclarationKind::BlockLocalItem);
                    }
                    p.facts
                        .add_gap(authored, ResolutionGapKind::UnsupportedScopeOrBinder);
                }
                if let Some(owned) = scope_by_node.get(&operation.id()) {
                    p.facts.scopes[owned.index()].owner = Some(authored);
                }
                Some(authored)
            }
            ResolutionBindingEventKind::Delete | ResolutionBindingEventKind::Annotation => None,
            ResolutionBindingEventKind::Parameter
            | ResolutionBindingEventKind::Assign
            | ResolutionBindingEventKind::Augment
            | ResolutionBindingEventKind::Import
            | ResolutionBindingEventKind::Iteration
            | ResolutionBindingEventKind::With
            | ResolutionBindingEventKind::Exception
            | ResolutionBindingEventKind::Pattern => {
                let authored = p.identifier(
                    token,
                    scope,
                    ResolutionSiteKind::ValueDeclaration,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                );
                let declaration_node = if matches!(
                    kind,
                    ResolutionBindingEventKind::Assign | ResolutionBindingEventKind::Augment
                ) {
                    find_ancestor(operation, |node| node.kind() == "expression_statement")
                        .unwrap_or(operation)
                } else {
                    token
                };
                let declaration = p.collector.declare_node(declaration_node, Some(token));
                p.declarations.push((authored, declaration));
                if let Some(unit) = units.get(&declaration) {
                    p.facts.definition_units.push(ResolutionDefinitionUnitFact {
                        declaration: authored,
                        unit: (*unit).clone(),
                    });
                } else {
                    // Supported lexical writes have their own source declaration,
                    // distinct from the binding slot, without requiring a CodeUnit.
                    p.collector.mark_lexical(
                        declaration,
                        binding_presentation_kind(token, p.facts.scopes[slot_scope.index()].kind),
                    );
                }
                Some(authored)
            }
        };
        let value = None;
        let ordinal = dense_ordinal(p.facts.binding_events.len(), "Python binding events");
        event_by_token.insert(token.id(), ordinal);
        p.facts.binding_events.push(ResolutionBindingEventFact {
            ordinal,
            slot,
            target,
            kind,
            value,
            authored_declaration: authored,
            source_reference: None,
        });
        temporal::timing(&mut p, ordinal, operation, execution_scope, false);
        if kind == ResolutionBindingEventKind::Exception {
            let ordinal = dense_ordinal(p.facts.binding_events.len(), "Python cleanup events");
            p.facts.binding_events.push(ResolutionBindingEventFact {
                ordinal,
                slot,
                target,
                kind: ResolutionBindingEventKind::Delete,
                value: None,
                authored_declaration: None,
                source_reference: None,
            });
            temporal::timing(&mut p, ordinal, operation, execution_scope, true);
        }
    }
    for (token, annotation, runtime) in generic_bindings {
        let declaration = p.identifier(
            token,
            annotation,
            ResolutionSiteKind::TypeDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        );
        let source_declaration = p.collector.declare_node(token, Some(token));
        p.collector
            .mark_lexical(source_declaration, DeclarationKind::Parameter);
        p.declarations.push((declaration, source_declaration));
        p.facts.binders.push(ResolutionBinderFact::scope_wide(
            declaration,
            ResolutionBinderKind::Type,
            p.facts.scopes[annotation.index()],
        ));
        p.facts.additional_definition_namespaces.push(
            ResolutionAdditionalDefinitionNamespaceFact {
                declaration,
                namespace: ResolutionNamespace::Value,
                hoisting: HoistingClass::ScopeWide,
            },
        );
        // One entry event initializes one cell, as for an ordinary parameter.
        // Annotation evaluation captures that cell through the existing
        // nonlocal route; runtime lookup reaches it without entering class locals.
        let slot = p.identifier(
            token,
            runtime,
            ResolutionSiteKind::BindingSlotDeclaration,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        );
        p.declarations.push((slot, source_declaration));
        p.facts.binding_slots.push(ResolutionBindingSlotFact {
            declaration: slot,
            lookup: ResolutionBindingLookup::WholeScope,
        });
        p.facts.binders.push(ResolutionBinderFact::scope_wide(
            slot,
            ResolutionBinderKind::Parameter,
            p.facts.scopes[runtime.index()],
        ));
        let target = p.identifier(
            token,
            annotation,
            ResolutionSiteKind::ValueReference,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        alias(&mut p, token, annotation, slot);
        p.facts
            .binding_directives
            .push(ResolutionBindingDirectiveFact {
                reference: target,
                kind: ResolutionBindingDirectiveKind::Nonlocal,
                target: Some(slot),
            });
        let ordinal = dense_ordinal(
            p.facts.binding_events.len(),
            "Python generic parameter events",
        );
        p.facts.binding_events.push(ResolutionBindingEventFact {
            ordinal,
            slot,
            target,
            kind: ResolutionBindingEventKind::Parameter,
            value: None,
            authored_declaration: Some(declaration),
            source_reference: None,
        });
        let entry = p.facts.scopes[runtime.index()].start_byte;
        p.facts
            .binding_event_timings
            .push(ResolutionBindingEventTimingFact {
                event: ordinal,
                execution_scope: runtime,
                entry_byte: entry,
                commit_byte: entry,
                commit_phase: 0,
            });
        // The lowerer adds the target's extra Value namespace to this route.
        let alias = p.identifier(
            token,
            runtime,
            ResolutionSiteKind::AliasBinding,
            ResolutionIdentifierRole::Alias,
            ResolutionNamespace::Type,
        );
        p.facts.binders.push(ResolutionBinderFact::scope_wide(
            alias,
            ResolutionBinderKind::Alias {
                target: declaration,
            },
            p.facts.scopes[runtime.index()],
        ));
    }
    exports::produce(&mut p, &nodes, &node_scopes, &event_by_token);
    // File-local facts use a symbolic package anchor; staging joins only
    // package markers and supplies their selected directory.
    p.facts.python_package_path_extensions = crate::package_paths::appended_path_dirs(root, source)
        .into_iter()
        .enumerate()
        .map(|(ordinal, directory)| PythonPackagePathExtensionFact {
            ordinal: u32::try_from(ordinal).expect("package extension ordinal"),
            directory: brokk_bifrost_core::path_utils::workspace_relative_slash_path(&directory),
        })
        .collect();
    for node in nodes.iter().copied() {
        let scope = node_scopes[&node.id()];
        match node.kind() {
            "import_statement" | "import_from_statement" => {
                imports::produce(&mut p, node, scope, &event_by_token);
            }
            "dotted_name"
                if node.named_child_count() > 1
                    && find_ancestor(node, |parent| {
                        matches!(parent.kind(), "import_statement" | "import_from_statement")
                    })
                    .is_none() =>
            {
                p.omitted_reference(node, scope)
            }
            "global_statement" | "nonlocal_statement" => {
                for token in named_children_iter(node).filter(|child| child.kind() == "identifier")
                {
                    let name = source[token.byte_range()].to_owned();
                    let kind = if node.kind() == "global_statement" {
                        ResolutionBindingDirectiveKind::Global
                    } else {
                        ResolutionBindingDirectiveKind::Nonlocal
                    };
                    let target_scope = if kind == ResolutionBindingDirectiveKind::Global {
                        Some(ResolutionScopeId::new(0))
                    } else {
                        find_scope_in_chain(
                            p.facts.scopes[scope.index()].parent,
                            |id| p.facts.scopes[id.index()].parent,
                            |id| {
                                matches!(
                                    scopes[id.index()].node.kind(),
                                    "function_definition" | "lambda"
                                ) && slots.contains_key(&(id, name.clone()))
                            },
                        )
                    };
                    let target = target_scope.and_then(|scope| slots.get(&(scope, name)).copied());
                    let reference = p.identifier(
                        token,
                        scope,
                        ResolutionSiteKind::ValueReference,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Value,
                    );
                    p.facts
                        .binding_directives
                        .push(ResolutionBindingDirectiveFact {
                            reference,
                            kind,
                            target,
                        });
                    if let Some(target) = target {
                        if p.facts.sites[target.index()].scope != scope
                            && redirected.insert((scope, target))
                        {
                            alias(&mut p, token, scope, target);
                        }
                    } else {
                        let name = p
                            .facts
                            .identifiers
                            .last()
                            .expect("directive reference identifier")
                            .name;
                        p.facts.add_route_gap(
                            reference,
                            ResolutionRouteGap::UnknownBinder {
                                scope,
                                name: Some(name),
                                namespace: Some(ResolutionNamespace::Value),
                                may_publish: false,
                            },
                        );
                    }
                }
            }
            "identifier" | "keyword_identifier" if !binding_tokens.contains(&node.id()) => {
                if node.parent().is_some_and(|parent| {
                    matches!(parent.kind(), "global_statement" | "nonlocal_statement")
                }) || python_keyword_argument_label(node)
                {
                    continue;
                }
                if node.parent().is_some_and(|parent| {
                    parent.kind() == "dotted_name" && parent.named_child_count() > 1
                }) {
                    // Flat dotted patterns require a qualified route, never an
                    // unrelated local-variable lookup of their terminal name.
                    continue;
                }
                // Typed syntax owns generic arguments and formal bounds. Its
                // producer emits their references without extra runtime sites.
                if find_ancestor(node, |ancestor| ancestor.kind() == "type_parameter").is_some() {
                    continue;
                }
                let implicit_class_cell = &source[node.byte_range()] == "__class__"
                    && p.facts.scopes[scope.index()].kind == ResolutionScopeKind::Executable
                    && find_scope_in_chain(
                        Some(scope),
                        |id| parents[&id],
                        |id| {
                            p.facts.scopes[id.index()].kind == ResolutionScopeKind::TypeBody
                                || slots.contains_key(&(id, "__class__".to_owned()))
                        },
                    )
                    .is_some_and(|id| {
                        p.facts.scopes[id.index()].kind == ResolutionScopeKind::TypeBody
                    });
                if python_node_is_in_annotation(node) || implicit_class_cell {
                    let site = p.site(node, scope, ResolutionSiteKind::UnsupportedExpression);
                    p.facts
                        .add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
                    p.facts.add_reference_enumeration_gap(
                        site,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    );
                    continue;
                }
                if node
                    .parent()
                    .is_some_and(|parent| is_field_child(parent, node, "attribute"))
                {
                    p.identifier(
                        node,
                        scope,
                        ResolutionSiteKind::MemberReference,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Value,
                    );
                    continue;
                }
                // Import paths and aliases remain the structural import producer's
                // authority until native route production; never index path pieces
                // as unrelated lexical variables.
                let mut parent = node.parent();
                let mut in_import = false;
                while let Some(ancestor) = parent {
                    if matches!(
                        ancestor.kind(),
                        "import_statement" | "import_from_statement"
                    ) {
                        in_import = true;
                        break;
                    }
                    if matches!(ancestor.kind(), "block" | "module") {
                        break;
                    }
                    parent = ancestor.parent();
                }
                if !in_import {
                    p.identifier(
                        node,
                        scope,
                        ResolutionSiteKind::ValueReference,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Value,
                    );
                }
            }
            // Typed annotation production owns quoted references and their slots.
            "string" if python_node_is_in_annotation(node) => {}
            "type_parameter" if !formal_lists.contains(&node.id()) => {
                let site = p.site(node, scope, ResolutionSiteKind::UnsupportedExpression);
                p.facts
                    .add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
                p.facts.add_reference_enumeration_gap(
                    site,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                );
            }

            "ERROR" => p.gap(node, scope, ResolutionGapKind::MalformedSyntax),
            _ => {}
        }
    }
    if root.has_error() {
        p.gap(
            root,
            ResolutionScopeId::new(0),
            ResolutionGapKind::MalformedSyntax,
        );
    }
    typed::produce(
        &mut p,
        &nodes,
        node_scopes,
        &scope_by_node,
        &event_by_token,
        &formal_lists,
        &units,
        receiver_fields,
    );
    imports::finish(&mut p);
    temporal::finish(
        &mut p,
        &scopes,
        future_annotations_enabled(&nodes, source),
        &generic_annotation_scopes,
        &generic_runtime_scopes,
    );
    p.facts.reference_lookup_requests.extend(
        p.facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| identifier.site),
    );
    // File modules have path-derived identities. Blob facts own only the
    // nameless declaration; the selected mount supplies the module's path.
    let scope = ResolutionScopeId::new(0);
    let site = p.site(root, scope, ResolutionSiteKind::ModuleDeclaration);
    p.facts
        .define_module(site, ResolutionNamespace::Value, Some(scope));
    p.facts.route_owned_module_declarations.push(site);
    let declaration = p.collector.declare_node(root, None);
    p.declarations.push((site, declaration));
    guards::validate(&p.facts);
    (p.facts, p.occurrences, p.declarations)
}

fn binding_presentation_kind(token: Node<'_>, scope: ResolutionScopeKind) -> DeclarationKind {
    match binding_operation(token) {
        (ResolutionBindingEventKind::Parameter, parameter)
            if parameter.kind() == "lambda_parameters" =>
        {
            DeclarationKind::LambdaParameter
        }
        (ResolutionBindingEventKind::Parameter, _) => DeclarationKind::Parameter,
        _ if scope == ResolutionScopeKind::CompilationUnit => DeclarationKind::Field,
        _ => DeclarationKind::LocalVariable,
    }
}

fn make_slot(
    p: &mut Producer<'_, '_>,
    token: Node<'_>,
    scope: ResolutionScopeId,
) -> ResolutionSiteId {
    let site = p.identifier(
        token,
        scope,
        ResolutionSiteKind::BindingSlotDeclaration,
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Value,
    );
    let declaration = p.collector.declare_node(token, Some(token));
    p.collector.mark_lexical(
        declaration,
        binding_presentation_kind(token, p.facts.scopes[scope.index()].kind),
    );
    p.declarations.push((site, declaration));
    let fact = p.facts.scopes[scope.index()];
    let lookup = if fact.kind == ResolutionScopeKind::Executable {
        ResolutionBindingLookup::WholeScope
    } else {
        ResolutionBindingLookup::Ordered
    };
    p.facts.binding_slots.push(ResolutionBindingSlotFact {
        declaration: site,
        lookup,
    });
    let mut binder = ResolutionBinderFact::scope_wide(site, ResolutionBinderKind::Local, fact);
    if lookup == ResolutionBindingLookup::Ordered {
        binder.hoisting = HoistingClass::SourceOrder;
        let operation = binding_operation(token).1;
        let body_entry = match operation.kind() {
            "for_statement" => operation.child_by_field_name("body"),
            "case_clause" => operation
                .child_by_field_name("guard")
                .or_else(|| operation.child_by_field_name("consequence")),
            "except_clause" => named_children_iter(operation).find(|child| child.kind() == "block"),
            _ => None,
        };
        binder.activation_start = body_entry.map_or(operation.end_byte(), |body| body.start_byte());
    }
    p.facts.binders.push(binder);
    site
}

fn alias(
    p: &mut Producer<'_, '_>,
    token: Node<'_>,
    scope: ResolutionScopeId,
    target: ResolutionSiteId,
) {
    let site = p.identifier(
        token,
        scope,
        ResolutionSiteKind::AliasBinding,
        ResolutionIdentifierRole::Alias,
        ResolutionNamespace::Value,
    );
    p.facts.binders.push(ResolutionBinderFact::scope_wide(
        site,
        ResolutionBinderKind::Alias { target },
        p.facts.scopes[scope.index()],
    ));
}

fn binding_operation(token: Node<'_>) -> (ResolutionBindingEventKind, Node<'_>) {
    let mut current = token;
    while let Some(parent) = current.parent() {
        let kind = match parent.kind() {
            "parameters" | "lambda_parameters" => Some(ResolutionBindingEventKind::Parameter),
            "function_definition" => Some(ResolutionBindingEventKind::Function),
            "class_definition" => Some(ResolutionBindingEventKind::Class),
            "type_alias_statement" => Some(ResolutionBindingEventKind::Assign),
            "assignment" if parent.child_by_field_name("right").is_none() => {
                Some(ResolutionBindingEventKind::Annotation)
            }
            "assignment" | "named_expression" => Some(ResolutionBindingEventKind::Assign),
            "augmented_assignment" => Some(ResolutionBindingEventKind::Augment),
            "delete_statement" => Some(ResolutionBindingEventKind::Delete),
            "for_statement" | "for_in_clause" => Some(ResolutionBindingEventKind::Iteration),
            "import_statement" | "import_from_statement" => {
                Some(ResolutionBindingEventKind::Import)
            }
            "except_clause" => Some(ResolutionBindingEventKind::Exception),
            "with_item" => Some(ResolutionBindingEventKind::With),
            "case_clause" => Some(ResolutionBindingEventKind::Pattern),
            _ => None,
        };
        if let Some(kind) = kind {
            return (kind, parent);
        }
        current = parent;
    }
    (ResolutionBindingEventKind::Assign, token)
}

/// Grammar-selected assignment-expression restrictions, including the PEP 572
/// prohibition on rebinding an iteration variable in an enclosing comprehension.
fn invalid_walrus(mut expression: Node<'_>, name: &str, source: &str) -> bool {
    let mut in_comprehension = false;
    while let Some(ancestor) = find_ancestor(expression, |node| {
        is_comprehension(node.kind())
            || matches!(
                node.kind(),
                "for_in_clause" | "function_definition" | "lambda" | "class_definition" | "module"
            )
    }) {
        match ancestor.kind() {
            "for_in_clause" => {
                let mut cursor = ancestor.walk();
                if ancestor
                    .children_by_field_name("right", &mut cursor)
                    .any(|right| {
                        right.start_byte() <= expression.start_byte()
                            && expression.end_byte() <= right.end_byte()
                    })
                {
                    return true;
                }
            }
            "class_definition" => return in_comprehension,
            "function_definition" | "lambda" | "module" => return false,
            _ => {
                in_comprehension = true;
                for clause in
                    named_children_iter(ancestor).filter(|node| node.kind() == "for_in_clause")
                {
                    if let Some(target) = clause.child_by_field_name("left") {
                        let mut conflict = false;
                        collect_binding_targets(target, source, &mut || true, |candidate, _| {
                            conflict |= candidate == name
                        })
                        .expect("unbounded comprehension target inventory");
                        if conflict {
                            return true;
                        }
                    }
                }
            }
        }
        expression = ancestor;
    }
    false
}
