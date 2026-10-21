//! A bounded, syntax-backed proof of the Rust ownership class of a type.
//!
//! This module deliberately answers a smaller question than rustc.  It only
//! proves facts that are present in the syntax tree passed by the caller:
//! primitive and recursively aggregate `Copy`, local nominal declarations
//! with exact builtin trait evidence, ordinary moves, and references.  A
//! missing workspace/index fact is an incomplete answer, never a guess.
//!
//! The index owns no parser or analyzer state.  Building it is therefore safe
//! to do during semantic materialization: every syntax visit and every
//! fixed-point pass goes through the caller's charge callback.

use crate::declarations::rust_node_text;
use crate::graph_support::{
    rust_path_is_leading_absolute, rust_path_is_leading_absolute_bounded, rust_path_segments,
    rust_path_segments_bounded,
};
use crate::imports::RustImportBindingName;
use crate::lexical_scope::{RustTypeHead, rust_type_head_at_bounded};
use crate::prelude::rust_std_type_fact;
use crate::syntax::unwrap_attributes;
use brokk_bifrost_core::analyzer::tree_walk::{
    has_child_of_kind as has_anonymous_child, named_children_vec as named_children,
};
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use tree_sitter::Node;

/// The ownership fact used by Rust semantic lowering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustOwnershipClass {
    /// A value with a scalar builtin type whose value can be copied.
    ScalarCopy,
    /// A value with an array, tuple, or proven local nominal type that can be
    /// copied.  Unlike a reference, a copy here receives distinct storage.
    AggregateCopy,
    /// A by-value operation consumes the source value.
    Move,
    /// A shared reference preserves aliasing.
    SharedReference,
    /// A mutable reference preserves aliasing.
    MutableReference,
    /// The tree contains an operation or type fact this bounded producer does
    /// not prove.
    Incomplete(RustOwnershipIncomplete),
}

/// Why a Rust ownership classification is incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustOwnershipIncomplete {
    GenericObligation,
    AmbiguousIdentity,
    UnresolvedPath,
    RawPointer,
    MacroExpansion,
    WrongTraitIdentity,
    CyclicNominal,
    MissingType,
    UnsupportedType,
}

/// The exact non-call reference coercions this producer can prove.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustReferenceCoercion {
    SharedAlias,
    MutableAlias,
    MutableToSharedReborrow,
    ArrayReferenceToSlice,
    Incomplete(RustOwnershipIncomplete),
}

/// The declaration identity of a local nominal type.
///
/// The source anchor is part of the identity even when two declarations have
/// the same lexical path.  The latter is how cfg alternatives and malformed
/// duplicate declarations remain ambiguous instead of silently overwriting a
/// map entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RustNominalIdentity {
    module_path: Vec<String>,
    name: String,
    source_start: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TraitEvidence {
    copy_count: usize,
    clone_count: usize,
    drop_count: usize,
    negative_copy: bool,
    wrong_builtin_count: usize,
    malformed_derive: bool,
    derive_copy: bool,
    derive_clone: bool,
    derive_copy_qualified: bool,
    derive_clone_qualified: bool,
}

impl TraitEvidence {
    fn has_copy_proof(&self, builtin_root_shadowed: bool) -> bool {
        let derived_copy = self.derive_copy && self.derive_copy_qualified && !builtin_root_shadowed;
        let derived_clone =
            self.derive_clone && self.derive_clone_qualified && !builtin_root_shadowed;
        (self.copy_count == 1 || derived_copy)
            && (self.clone_count == 1 || derived_clone)
            && self.wrong_builtin_count == 0
            && !self.malformed_derive
    }

    fn has_invalid_copy_claim(&self, builtin_root_shadowed: bool) -> bool {
        self.wrong_builtin_count != 0
            || self.malformed_derive
            || self.copy_count > 1
            || self.clone_count > 1
            || (self.derive_copy && !self.derive_copy_qualified)
            || (self.derive_clone && !self.derive_clone_qualified)
            || (self.derive_copy && self.derive_copy_qualified && builtin_root_shadowed)
            || (self.derive_clone && self.derive_clone_qualified && builtin_root_shadowed)
            || (self.copy_count != 0 && self.clone_count == 0 && !self.derive_clone)
            || (self.derive_copy && self.clone_count == 0 && !self.derive_clone)
    }
}

#[derive(Clone, Debug)]
struct NominalDeclaration<'tree> {
    identity: RustNominalIdentity,
    payload_types: Vec<Node<'tree>>,
    struct_drop_fields: Option<Vec<(Option<Node<'tree>>, Node<'tree>)>>,
    generic: bool,
    generic_drop_obligation: bool,
    malformed_payload: bool,
    evidence: TraitEvidence,
    drop_impl_method: Option<Node<'tree>>,
    drop_impl_ambiguous: bool,
}

#[derive(Clone, Debug)]
struct ImportBinding {
    module_path: Vec<String>,
    local_name: String,
    target_path: Vec<String>,
    wildcard: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ShadowedBinding {
    module_path: Vec<String>,
    name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NominalState {
    Pending,
    Copy,
    Move,
    Incomplete(RustOwnershipIncomplete),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvalState {
    Copy,
    Move,
    Pending,
    Incomplete(RustOwnershipIncomplete),
}

enum TypeEvaluation<'tree> {
    Leaf(EvalState),
    Alias(Node<'tree>),
    Option(Node<'tree>),
    Aggregate(Vec<Node<'tree>>),
}

#[derive(Clone, Debug)]
struct PendingImpl<'tree> {
    module_path: Vec<String>,
    node: Node<'tree>,
    trait_node: Option<Node<'tree>>,
    target_node: Node<'tree>,
    negative: bool,
    generic: bool,
}

/// The bounded ownership/type/trait producer for one Rust syntax tree.
#[derive(Debug)]
pub struct RustOwnershipIndex<'tree, 'source> {
    source: &'source str,
    root: Node<'tree>,
    declarations: Vec<NominalDeclaration<'tree>>,
    by_path: HashMap<Vec<String>, Vec<usize>>,
    imports: Vec<ImportBinding>,
    shadowed_names: HashSet<ShadowedBinding>,
    states: HashMap<usize, NominalState>,
    module_context_by_node: HashMap<usize, Option<usize>>,
    lexical_modules: Vec<LexicalModuleContext>,
    #[cfg(test)]
    lexical_module_context_steps: AtomicUsize,
}

impl<'tree, 'source> RustOwnershipIndex<'tree, 'source> {
    /// Scan declarations, exact local trait evidence, and lexical imports,
    /// then solve nominal payload dependencies to a fixed point.
    pub fn build<F, E>(root: Node<'tree>, source: &'source str, mut charge: F) -> Result<Self, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        let mut declarations = Vec::new();
        let mut pending_impls = Vec::new();
        let mut imports = Vec::new();
        let mut shadowed_names = HashSet::new();
        let mut module_context_by_node = HashMap::new();
        let mut lexical_modules = Vec::new();
        let mut stack = vec![ScanFrame {
            node: root,
            module_path: Vec::new(),
            module_context: None,
            under_macro: false,
        }];

        while let Some(frame) = stack.pop() {
            charge(1)?;
            let node = unwrap_attributes(frame.node);
            module_context_by_node.insert(frame.node.id(), frame.module_context);
            module_context_by_node.insert(node.id(), frame.module_context);
            let macro_context =
                frame.under_macro || matches!(node.kind(), "macro_invocation" | "macro_definition");

            if node.kind() == "use_declaration" && !macro_context {
                collect_imports(
                    node,
                    source,
                    &frame.module_path,
                    &mut imports,
                    &mut shadowed_names,
                    &mut charge,
                )?;
            }

            if !macro_context {
                if let Some(declaration) =
                    nominal_declaration(node, source, &frame.module_path, &mut shadowed_names)
                {
                    declarations.push(declaration);
                }
                if node.kind() == "impl_item" {
                    pending_impls.push(PendingImpl {
                        module_path: frame.module_path.clone(),
                        node,
                        trait_node: node.child_by_field_name("trait"),
                        target_node: node
                            .child_by_field_name("type")
                            .expect("Rust impl items always have a target type"),
                        negative: has_anonymous_child(node, "!"),
                        generic: node.child_by_field_name("type_parameters").is_some()
                            || has_where_clause(node),
                    });
                }
            }

            let mut child_module_path = frame.module_path.clone();
            let mut child_module_context = frame.module_context;
            if !macro_context
                && node.kind() == "mod_item"
                && let Some(name) = node
                    .child_by_field_name("name")
                    .filter(|name| name.kind() == "identifier")
                    .map(|name| rust_node_text(name, source).to_string())
            {
                child_module_path.push(name.clone());
                child_module_context = Some(lexical_modules.len());
                lexical_modules.push(LexicalModuleContext {
                    parent: frame.module_context,
                    name,
                });
            }

            let children = named_children(node);
            for child in children.into_iter().rev() {
                stack.push(ScanFrame {
                    node: child,
                    module_path: if node.kind() == "mod_item" {
                        child_module_path.clone()
                    } else {
                        frame.module_path.clone()
                    },
                    module_context: if node.kind() == "mod_item" {
                        child_module_context
                    } else {
                        frame.module_context
                    },
                    under_macro: macro_context,
                });
            }
        }

        let mut by_path: HashMap<Vec<String>, Vec<usize>> = HashMap::new();
        for (index, declaration) in declarations.iter().enumerate() {
            by_path
                .entry(declaration_path(declaration))
                .or_default()
                .push(index);
        }

        let mut index = Self {
            source,
            root,
            declarations,
            by_path,
            imports,
            shadowed_names,
            states: HashMap::new(),
            module_context_by_node,
            lexical_modules,
            #[cfg(test)]
            lexical_module_context_steps: AtomicUsize::new(0),
        };
        for declaration_index in 0..index.declarations.len() {
            index
                .states
                .insert(declaration_index, NominalState::Pending);
        }

        for implementation in pending_impls {
            charge(1)?;
            index.apply_impl(implementation);
        }

        // A monotonic fixed point is enough: Pending becomes Copy, Move, or
        // Incomplete and never changes again.  The final pass below turns a
        // genuinely cyclic dependency into typed incompleteness.
        loop {
            let mut changed = false;
            for declaration_index in 0..index.declarations.len() {
                charge(1)?;
                let next = index.evaluate_declaration(declaration_index);
                let current = index
                    .states
                    .get(&declaration_index)
                    .copied()
                    .expect("all declarations receive an initial state");
                if next != NominalState::Pending && next != current {
                    index.states.insert(declaration_index, next);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        Ok(index)
    }

    /// Classify an exact Rust type node from the tree used to build this
    /// index.
    /// Give admitted operand nodes their opaque anchor's lexical module.
    /// This does not promote macro-written declarations or imports to primary
    /// authority; it only lets ordinary expression queries use exact nodes.
    pub fn register_embedded_syntax<F, E>(
        &mut self,
        forest: &brokk_bifrost_core::analyzer::structural::spec::EmbeddedSyntaxForest,
        mut charge: F,
    ) -> Result<(), E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        forest.for_each_node(|anchor, node| {
            charge(1)?;
            let context = *self
                .module_context_by_node
                .get(&anchor)
                .expect("embedded syntax anchor belongs to the indexed primary or parent fragment");
            self.module_context_by_node.insert(node.id(), context);
            Ok(())
        })
    }

    pub fn classify_type(&self, type_node: Node<'tree>) -> RustOwnershipClass {
        if has_macro_ancestor(type_node) {
            return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MacroExpansion);
        }
        if has_unsafe_ancestor(type_node) {
            return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        }
        if type_node.kind() == "reference_type" {
            return classify_reference_type_bounded(type_node, &mut |_| {
                Ok::<_, std::convert::Infallible>(())
            })
            .expect("infallible legacy reference classification");
        }
        let state = self.classify_type_state(type_node);
        if type_node.kind() == "primitive_type" {
            return match state {
                EvalState::Copy => RustOwnershipClass::ScalarCopy,
                EvalState::Incomplete(reason) => RustOwnershipClass::Incomplete(reason),
                EvalState::Move => RustOwnershipClass::Move,
                EvalState::Pending => {
                    RustOwnershipClass::Incomplete(RustOwnershipIncomplete::CyclicNominal)
                }
            };
        }
        state.into_public()
    }

    /// Prove the ordered, owned tuple layout of this exact source type.
    /// #5911: aliases are evaluated in their declaration's scope, never in
    /// the destructuring caller's scope. Callback failure publishes no layout.
    pub fn tuple_component_types_bounded<F, E>(
        &self,
        type_node: Node<'tree>,
        mut charge: F,
    ) -> Result<Result<Vec<Node<'tree>>, RustOwnershipIncomplete>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        let node = match self.normalized_type_bounded(type_node, &mut charge)? {
            Ok(node) => node,
            Err(reason) => return Ok(Err(reason)),
        };
        if node.kind() != "tuple_type" {
            return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
        }
        let mut components = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            charge(1)?;
            if matches!(child.kind(), "line_comment" | "block_comment") {
                continue;
            }
            if !is_type_node(child) {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            components.push(child);
        }
        charge(0)?;
        Ok(Ok(components))
    }

    fn normalized_type_bounded<F, E>(
        &self,
        mut node: Node<'tree>,
        charge: &mut F,
    ) -> Result<Result<Node<'tree>, RustOwnershipIncomplete>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        charge(0)?;
        let mut ancestor = Some(node);
        loop {
            charge(1)?;
            let Some(current) = ancestor else {
                return Ok(Err(RustOwnershipIncomplete::UnresolvedPath));
            };
            if current.id() == self.root.id() {
                break;
            }
            ancestor = current.parent();
        }
        let mut visited = HashSet::new();
        loop {
            charge(1)?;
            if !visited.insert(node.id()) {
                return Ok(Err(RustOwnershipIncomplete::CyclicNominal));
            }
            if node.has_error()
                || has_macro_ancestor_bounded(node, charge)?
                || has_unsafe_ancestor_bounded(node, charge)?
            {
                return Ok(Err(RustOwnershipIncomplete::UnsupportedType));
            }
            if let Some(inner) = crate::type_syntax::rust_parenthesized_type_inner(node) {
                node = inner;
                continue;
            }
            if matches!(
                node.kind(),
                "primitive_type" | "type_identifier" | "scoped_type_identifier" | "generic_type"
            ) {
                match self.type_expansion_bounded(node, charge)? {
                    Some(TypeEvaluation::Alias(target)) => {
                        node = target;
                        continue;
                    }
                    Some(TypeEvaluation::Leaf(EvalState::Incomplete(reason))) => {
                        return Ok(Err(reason));
                    }
                    _ => {}
                }
            }
            charge(0)?;
            return Ok(Ok(node));
        }
    }

    /// Ownership for tuple components, including transparent nongeneric
    /// aliases and the independently proven conditional Copy of std Option.
    /// New proof work uses the caller's existing work/cancellation callback.
    pub fn classify_type_bounded<F, E>(
        &self,
        type_node: Node<'tree>,
        mut charge: F,
    ) -> Result<RustOwnershipClass, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        let type_node = match self.normalized_type_bounded(type_node, &mut charge)? {
            Ok(node) => node,
            Err(reason) => return Ok(RustOwnershipClass::Incomplete(reason)),
        };
        // References retain their alias/reborrow class; a tuple referent is
        // not permission to copy or move the owned tuple behind the borrow.
        if type_node.kind() == "reference_type" {
            // Normalization already checked the alias RHS ancestry with this
            // callback. Classify the reference without re-entering legacy walks.
            return classify_reference_type_bounded(type_node, &mut charge);
        }
        let state =
            self.evaluate_type_state_bounded(type_node, &mut charge, &mut |node, charge| {
                self.type_expansion_bounded(node, charge)
            })?;
        charge(0)?;
        Ok(
            if type_node.kind() == "primitive_type" && state == EvalState::Copy {
                RustOwnershipClass::ScalarCopy
            } else {
                state.into_public()
            },
        )
    }

    fn type_expansion_bounded<F, E>(
        &self,
        node: Node<'tree>,
        charge: &mut F,
    ) -> Result<Option<TypeEvaluation<'tree>>, E>
    where
        F: FnMut(usize) -> Result<(), E>,
    {
        if node.kind() == "tuple_type" {
            let mut children = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                charge(1)?;
                if matches!(child.kind(), "line_comment" | "block_comment") {
                    continue;
                }
                if !is_type_node(child) {
                    return Ok(Some(TypeEvaluation::Leaf(EvalState::Incomplete(
                        RustOwnershipIncomplete::UnsupportedType,
                    ))));
                }
                children.push(child);
            }
            return Ok(Some(TypeEvaluation::Aggregate(children)));
        }
        let name = if node.kind() == "generic_type" {
            let Some(name) = node.child_by_field_name("type") else {
                return Ok(Some(TypeEvaluation::Leaf(EvalState::Incomplete(
                    RustOwnershipIncomplete::MissingType,
                ))));
            };
            name
        } else {
            node
        };
        let path = if name.kind() == "primitive_type" {
            charge(1)?;
            vec![name]
        } else {
            let Some(path) = rust_path_segments_bounded(name, &mut *charge)? else {
                return Ok(None);
            };
            path
        };
        charge(path.len())?;
        let names = path
            .iter()
            .map(|node| rust_node_text(*node, self.source))
            .collect::<Vec<_>>();
        let Some(first) = names.first() else {
            return Ok(None);
        };
        let absolute = rust_path_is_leading_absolute_bounded(name, &mut *charge)?;
        let actual_head = rust_type_head_at_bounded(self.root, self.source, name, first, charge)?;
        let head = if absolute {
            // Keep activation/opaque-scope refusal at the actual site even
            // though an absolute name selects its head at the crate root.
            if matches!(actual_head, RustTypeHead::Unknown) {
                return Ok(Some(TypeEvaluation::Leaf(EvalState::Incomplete(
                    RustOwnershipIncomplete::UnresolvedPath,
                ))));
            }
            rust_type_head_at_bounded(self.root, self.source, self.root, first, charge)?
        } else {
            actual_head
        };
        if node.kind() != "generic_type"
            && names.len() == 1
            && !absolute
            && let RustTypeHead::Item(item) = &head
        {
            if item.kind() == "type_item" {
                let target = item.child_by_field_name("type");
                let valid = item.child_by_field_name("type_parameters").is_none()
                    && !has_where_clause_bounded(*item, charge)?;
                return Ok(Some(if valid {
                    target
                        .map(TypeEvaluation::Alias)
                        .unwrap_or(TypeEvaluation::Leaf(EvalState::Incomplete(
                            RustOwnershipIncomplete::MissingType,
                        )))
                } else {
                    TypeEvaluation::Leaf(EvalState::Incomplete(
                        RustOwnershipIncomplete::GenericObligation,
                    ))
                }));
            }
            // Preserve the exact selected local nominal, not a pooled
            // same-spelled declaration from another lexical block.
            let mut state = None;
            for (index, declaration) in self.declarations.iter().enumerate() {
                charge(1)?;
                if declaration.identity.source_start == item.start_byte() {
                    state = self.states.get(&index).copied();
                    break;
                }
            }
            return Ok(Some(TypeEvaluation::Leaf(match state {
                Some(NominalState::Copy) => EvalState::Copy,
                Some(NominalState::Move) => EvalState::Move,
                Some(NominalState::Pending) => EvalState::Pending,
                Some(NominalState::Incomplete(reason)) => EvalState::Incomplete(reason),
                None => EvalState::Incomplete(RustOwnershipIncomplete::UnresolvedPath),
            })));
        }
        if node.kind() == "primitive_type" {
            return Ok(Some(TypeEvaluation::Leaf(
                if matches!(head, RustTypeHead::Unbound) && is_copy_primitive(node, self.source) {
                    EvalState::Copy
                } else {
                    EvalState::Incomplete(RustOwnershipIncomplete::UnresolvedPath)
                },
            )));
        }
        if node.kind() == "generic_type" {
            // This is the specific language/library rule Option<T>: Copy
            // when T: Copy. The table supplies identity/arity, not Copy:
            // its inert-drop facts also include non-Copy String/Vec/Box.
            let option = rust_std_type_fact("Option").expect("reviewed Option identity and arity");
            assert_eq!(
                option.type_arguments, 1,
                "conditional Option Copy has one payload"
            );
            let canonical = match head {
                RustTypeHead::Unbound if names == ["Option"] && !absolute => true,
                RustTypeHead::Unbound => {
                    names.len() == option.path.len()
                        && matches!(names[0], "core" | "std")
                        && names[1..] == option.path[1..]
                }
                RustTypeHead::Import { path, declaration } => {
                    let mut target = path;
                    for name in names.iter().skip(1) {
                        charge(1)?;
                        charge(name.len())?;
                        target.push((*name).to_string());
                    }
                    // An import's own root is resolved at the import site by
                    // the shared selector, before it can supply std identity.
                    let root_unbound = if let Some(first) = target.first() {
                        matches!(
                            rust_type_head_at_bounded(
                                self.root,
                                self.source,
                                declaration,
                                first,
                                charge
                            )?,
                            RustTypeHead::Unbound
                        )
                    } else {
                        false
                    };
                    root_unbound
                        && target.len() == option.path.len()
                        && matches!(target[0].as_str(), "core" | "std")
                        && target.iter().skip(1).map(String::as_str).eq(option
                            .path
                            .iter()
                            .skip(1)
                            .copied())
                }
                _ => false,
            };
            if canonical {
                let arguments = node.child_by_field_name("type_arguments");
                let mut actual = Vec::new();
                if let Some(arguments) = arguments {
                    let mut cursor = arguments.walk();
                    for argument in arguments.named_children(&mut cursor) {
                        charge(1)?;
                        if !matches!(argument.kind(), "line_comment" | "block_comment") {
                            actual.push(argument);
                        }
                    }
                }
                if actual.len() == option.type_arguments
                    && actual.iter().all(|argument| is_type_node(*argument))
                {
                    return Ok(Some(TypeEvaluation::Option(actual[0])));
                }
            }
            return Ok(Some(TypeEvaluation::Leaf(EvalState::Incomplete(
                RustOwnershipIncomplete::GenericObligation,
            ))));
        }
        Ok(Some(TypeEvaluation::Leaf(EvalState::Incomplete(
            RustOwnershipIncomplete::UnresolvedPath,
        ))))
    }

    /// Classify a local nominal declaration for destructor queries.
    ///
    /// Unlike a transfer, destructor behavior does not depend on whether the
    /// type mention is inside unsafe code. A raw-pointer read can duplicate
    /// storage, but cannot change the declaration's Copy or Drop evidence.
    /// Macro expansion remains incomplete, as it does for transfer queries.
    pub fn classify_nominal_type_for_drop(&self, type_node: Node<'tree>) -> RustOwnershipClass {
        if has_macro_ancestor(type_node) {
            return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MacroExpansion);
        }
        self.classify_nominal_reference(type_node).into_public()
    }

    /// Resolve a local nominal type's exact, nongeneric `Drop::drop` body.
    ///
    /// This returns a method only when the impl's trait path resolved to the
    /// builtin `core::ops::Drop`/`std::ops::Drop` identity while building this
    /// index and the target type names one unique local declaration.
    pub fn drop_impl_method_for_type(
        &self,
        type_node: Node<'tree>,
    ) -> Result<Option<Node<'tree>>, RustOwnershipIncomplete> {
        let index = self.unique_nominal_candidate_index(type_node)?;
        let declaration = &self.declarations[index];
        if declaration.generic_drop_obligation {
            return Err(RustOwnershipIncomplete::GenericObligation);
        }
        match declaration.evidence.drop_count {
            0 => Ok(None),
            1 if !declaration.drop_impl_ambiguous => declaration
                .drop_impl_method
                .map(Some)
                .ok_or(RustOwnershipIncomplete::UnsupportedType),
            _ => Err(RustOwnershipIncomplete::AmbiguousIdentity),
        }
    }

    /// Return a local struct's fields in declaration order for Rust drop glue.
    ///
    /// Enum fields are variant-dependent and unions have no implicit field
    /// drop order, so those shapes remain explicitly incomplete to the caller.
    pub fn drop_fields_for_type(
        &self,
        type_node: Node<'tree>,
    ) -> Result<Vec<(Option<Node<'tree>>, Node<'tree>)>, RustOwnershipIncomplete> {
        let index = self.unique_nominal_candidate_index(type_node)?;
        let declaration = &self.declarations[index];
        if declaration.generic_drop_obligation {
            return Err(RustOwnershipIncomplete::GenericObligation);
        }
        declaration
            .struct_drop_fields
            .clone()
            .ok_or(RustOwnershipIncomplete::UnsupportedType)
    }

    /// Prove that one structured Rust path from the indexed tree names an
    /// exact standard-library item, accounting for lexical imports, aliases,
    /// and shadowing.
    ///
    /// `expected` is the canonical path, such as `core::ptr::read`. The
    /// standard prelude is consulted only for language-defined names and only
    /// when no local or imported binding shadows that name.
    pub fn resolves_standard_path(&self, path_node: Node<'tree>, expected: &[&str]) -> bool {
        let Some(segments) = rust_path_segments(path_node) else {
            return false;
        };
        let names = segments
            .iter()
            .map(|segment| rust_node_text(*segment, self.source).to_string())
            .collect::<Vec<_>>();
        if names.is_empty() {
            return false;
        }
        let module_path = self.lexical_module_path(path_node);
        let absolute = rust_path_is_leading_absolute(path_node);
        let mut resolved = Vec::<Vec<String>>::new();

        if absolute {
            resolved.push(names.clone());
        } else {
            let first = names.first().expect("nonempty path has a first segment");
            let named_imports = self
                .imports
                .iter()
                .filter(|import| is_lexically_visible(&module_path, &import.module_path))
                .filter(|import| !import.wildcard && import.local_name == *first)
                .collect::<Vec<_>>();

            for import in &named_imports {
                let mut target =
                    resolve_standard_import_path(&import.module_path, &import.target_path);
                target.extend(names.iter().skip(1).cloned());
                resolved.push(target);
            }

            if named_imports.is_empty() && is_standard_root(first) {
                if !self.name_is_shadowed(&module_path, first) {
                    resolved.push(names.clone());
                }
            } else if named_imports.is_empty() {
                for import in self.imports.iter().filter(|import| {
                    import.wildcard && is_lexically_visible(&module_path, &import.module_path)
                }) {
                    let mut target =
                        resolve_standard_import_path(&import.module_path, &import.target_path);
                    target.extend(names.iter().cloned());
                    resolved.push(target);
                }
                if resolved.is_empty()
                    && is_standard_prelude_path(expected, &names)
                    && !self.name_is_shadowed(&module_path, first)
                {
                    resolved.push(expected.iter().map(|part| (*part).to_string()).collect());
                }
            }
        }

        resolved.sort_unstable();
        resolved.dedup();
        resolved.len() == 1
            && resolved[0]
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
    }

    fn lexical_module_path(&self, node: Node<'tree>) -> Vec<String> {
        let mut context = *self
            .module_context_by_node
            .get(&node.id())
            .expect("RustOwnershipIndex query nodes must come from its indexed syntax tree");
        let mut reversed = Vec::new();
        while let Some(context_id) = context {
            #[cfg(test)]
            self.lexical_module_context_steps
                .fetch_add(1, Ordering::Relaxed);
            let module = self
                .lexical_modules
                .get(context_id)
                .expect("module context id is recorded during the ownership scan");
            reversed.push(module.name.clone());
            context = module.parent;
        }
        reversed.reverse();
        reversed
    }

    /// Classify a literal transfer only when its AST category agrees with an
    /// exact builtin destination type. The destination supplies Rust's
    /// otherwise-inferred literal type without treating arbitrary spelling as
    /// trait evidence.
    pub fn classify_literal_for_type(
        &self,
        literal: Node<'tree>,
        type_node: Node<'tree>,
    ) -> RustOwnershipClass {
        let compatible = match literal.kind() {
            "integer_literal" => is_integer_primitive(type_node, self.source),
            "float_literal" => is_float_primitive(type_node, self.source),
            "char_literal" => is_named_primitive(type_node, self.source, "char"),
            "boolean_literal" | "true" | "false" => {
                is_named_primitive(type_node, self.source, "bool")
            }
            "unit_expression" => type_node.kind() == "unit_type",
            _ => false,
        };
        if compatible {
            self.classify_type(type_node)
        } else {
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType)
        }
    }

    /// Prove that two type nodes have the same exact structured type.  Paths
    /// are compared by their AST segments and local nominal resolution is
    /// required for each nominal segment; rendered spelling alone is never a
    /// proof of identity.
    pub fn exact_type_equivalence(
        &self,
        left: Node<'tree>,
        right: Node<'tree>,
    ) -> Result<bool, RustOwnershipIncomplete> {
        let mut pending = vec![(left, right)];
        while let Some((left, right)) = pending.pop() {
            if has_macro_ancestor(left) || has_macro_ancestor(right) {
                return Err(RustOwnershipIncomplete::MacroExpansion);
            }
            if has_unsafe_ancestor(left) || has_unsafe_ancestor(right) {
                return Err(RustOwnershipIncomplete::UnsupportedType);
            }
            if left.kind() != right.kind() {
                return Ok(false);
            }
            match left.kind() {
                "primitive_type" => {
                    if rust_node_text(left, self.source) != rust_node_text(right, self.source) {
                        return Ok(false);
                    }
                }
                "unit_type" => {}
                "integer_literal" | "float_literal" | "boolean_literal" | "char_literal" => {
                    if rust_node_text(left, self.source) != rust_node_text(right, self.source) {
                        return Ok(false);
                    }
                }
                "reference_type" => {
                    if reference_is_mutable(left) != reference_is_mutable(right) {
                        return Ok(false);
                    }
                    let left_referent =
                        reference_referent(left).ok_or(RustOwnershipIncomplete::MissingType)?;
                    let right_referent =
                        reference_referent(right).ok_or(RustOwnershipIncomplete::MissingType)?;
                    pending.push((left_referent, right_referent));
                }
                "array_type" => {
                    let left_element =
                        sequence_element(left).ok_or(RustOwnershipIncomplete::MissingType)?;
                    let right_element =
                        sequence_element(right).ok_or(RustOwnershipIncomplete::MissingType)?;
                    match (
                        left.child_by_field_name("length"),
                        right.child_by_field_name("length"),
                    ) {
                        (None, None) => {}
                        (Some(left_length), Some(right_length)) => {
                            pending.push((left_length, right_length));
                        }
                        _ => return Ok(false),
                    }
                    pending.push((left_element, right_element));
                }
                "tuple_type" => {
                    let left_children = named_children(left)
                        .into_iter()
                        .filter(|child| is_type_node(*child))
                        .collect::<Vec<_>>();
                    let right_children = named_children(right)
                        .into_iter()
                        .filter(|child| is_type_node(*child))
                        .collect::<Vec<_>>();
                    if left_children.len() != right_children.len() {
                        return Ok(false);
                    }
                    pending.extend(left_children.into_iter().zip(right_children));
                }
                "slice_type" => {
                    let left_element =
                        sequence_element(left).ok_or(RustOwnershipIncomplete::MissingType)?;
                    let right_element =
                        sequence_element(right).ok_or(RustOwnershipIncomplete::MissingType)?;
                    pending.push((left_element, right_element));
                }
                "type_identifier"
                | "identifier"
                | "scoped_type_identifier"
                | "scoped_identifier" => {
                    if !valid_path_shape(left)
                        || !valid_path_shape(right)
                        || contains_generic(left)
                        || contains_generic(right)
                    {
                        return Err(RustOwnershipIncomplete::GenericObligation);
                    }
                    let left_identity = self.nominal_identity_index(left)?;
                    let right_identity = self.nominal_identity_index(right)?;
                    if left_identity != right_identity {
                        return Ok(false);
                    }
                }
                "pointer_type" => return Err(RustOwnershipIncomplete::RawPointer),
                "generic_type" => {
                    return Err(RustOwnershipIncomplete::GenericObligation);
                }
                _ => return Err(RustOwnershipIncomplete::UnsupportedType),
            }
        }
        Ok(true)
    }

    /// Prove a non-call reference alias/coercion between source and target
    /// types.  The result is intentionally separate from ownership class:
    /// mutable-to-shared reborrow and array-reference unsizing both preserve
    /// alias identity but have distinct structural evidence.
    pub fn classify_reference_coercion(
        &self,
        source_type: Node<'tree>,
        target_type: Node<'tree>,
    ) -> RustReferenceCoercion {
        let Some(source_referent) = reference_referent(source_type) else {
            return RustReferenceCoercion::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        };
        let Some(target_referent) = reference_referent(target_type) else {
            return RustReferenceCoercion::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        };
        let source_mutable = reference_is_mutable(source_type);
        let target_mutable = reference_is_mutable(target_type);

        if !target_mutable && source_mutable {
            match self.exact_type_equivalence(source_referent, target_referent) {
                Ok(true) => return RustReferenceCoercion::MutableToSharedReborrow,
                Ok(false) => {}
                Err(reason) => return RustReferenceCoercion::Incomplete(reason),
            }
        }
        if source_mutable == target_mutable {
            match self.exact_type_equivalence(source_referent, target_referent) {
                Ok(true) => {
                    return if target_mutable {
                        RustReferenceCoercion::MutableAlias
                    } else {
                        RustReferenceCoercion::SharedAlias
                    };
                }
                Ok(false) => {}
                Err(reason) => return RustReferenceCoercion::Incomplete(reason),
            }
        }

        if source_referent.kind() == "array_type"
            && target_referent.kind() == "array_type"
            && source_referent.child_by_field_name("length").is_some()
            && target_referent.child_by_field_name("length").is_none()
        {
            let Some(source_element) = sequence_element(source_referent) else {
                return RustReferenceCoercion::Incomplete(RustOwnershipIncomplete::MissingType);
            };
            let Some(target_element) = sequence_element(target_referent) else {
                return RustReferenceCoercion::Incomplete(RustOwnershipIncomplete::MissingType);
            };
            match self.exact_type_equivalence(source_element, target_element) {
                Ok(true) => return RustReferenceCoercion::ArrayReferenceToSlice,
                Ok(false) => {}
                Err(reason) => return RustReferenceCoercion::Incomplete(reason),
            }
        }
        RustReferenceCoercion::Incomplete(RustOwnershipIncomplete::UnsupportedType)
    }

    fn classify_type_state(&self, type_node: Node<'tree>) -> EvalState {
        // Existing unbounded callers keep their original syntax-only envelope.
        // Alias/Option traversal is admitted only through the charged API.
        self.evaluate_type_state_bounded(
            type_node,
            &mut |_| Ok::<_, std::convert::Infallible>(()),
            &mut |_, _| Ok(None),
        )
        .expect("infallible legacy ownership evaluation")
    }

    fn evaluate_type_state_bounded<F, E, P>(
        &self,
        type_node: Node<'tree>,
        charge: &mut F,
        expand: &mut P,
    ) -> Result<EvalState, E>
    where
        F: FnMut(usize) -> Result<(), E>,
        P: FnMut(Node<'tree>, &mut F) -> Result<Option<TypeEvaluation<'tree>>, E>,
    {
        let mut values = HashMap::new();
        let mut plans = HashMap::new();
        let mut active = HashSet::new();
        let mut stack = vec![(type_node, false)];
        while let Some((node, finish)) = stack.pop() {
            charge(1)?;
            let key = node.id();
            if values.contains_key(&key) {
                continue;
            }
            if finish {
                let plan = plans.remove(&key).expect("scheduled ownership plan");
                let result = match plan {
                    TypeEvaluation::Alias(child) => values[&child.id()],
                    TypeEvaluation::Option(child) => match values[&child.id()] {
                        EvalState::Copy => EvalState::Copy,
                        EvalState::Pending => EvalState::Pending,
                        EvalState::Incomplete(reason) => EvalState::Incomplete(reason),
                        EvalState::Move => {
                            EvalState::Incomplete(RustOwnershipIncomplete::GenericObligation)
                        }
                    },
                    TypeEvaluation::Aggregate(children) => {
                        aggregate_result(children.iter().map(|child| values[&child.id()]))
                    }
                    TypeEvaluation::Leaf(_) => unreachable!("leaves finish immediately"),
                };
                active.remove(&key);
                values.insert(key, result);
                continue;
            }
            if !active.insert(key) {
                values.insert(
                    key,
                    EvalState::Incomplete(RustOwnershipIncomplete::CyclicNominal),
                );
                continue;
            }
            let plan = if has_macro_ancestor_bounded(node, charge)? {
                TypeEvaluation::Leaf(EvalState::Incomplete(
                    RustOwnershipIncomplete::MacroExpansion,
                ))
            } else if has_unsafe_ancestor_bounded(node, charge)? {
                TypeEvaluation::Leaf(EvalState::Incomplete(
                    RustOwnershipIncomplete::UnsupportedType,
                ))
            } else {
                match node.kind() {
                    "array_type" => match sequence_element(node) {
                        Some(element) => TypeEvaluation::Aggregate(vec![element]),
                        None => TypeEvaluation::Leaf(EvalState::Incomplete(
                            RustOwnershipIncomplete::MissingType,
                        )),
                    },
                    "tuple_type" => expand(node, charge)?.unwrap_or_else(|| {
                        TypeEvaluation::Aggregate(
                            named_children(node)
                                .into_iter()
                                .filter(|child| is_type_node(*child))
                                .collect(),
                        )
                    }),
                    "primitive_type" => expand(node, charge)?.unwrap_or_else(|| {
                        TypeEvaluation::Leaf(if is_copy_primitive(node, self.source) {
                            EvalState::Copy
                        } else {
                            EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType)
                        })
                    }),
                    "unit_type" => TypeEvaluation::Leaf(EvalState::Copy),
                    "reference_type" => TypeEvaluation::Leaf(match reference_referent(node) {
                        None => EvalState::Incomplete(RustOwnershipIncomplete::MissingType),
                        Some(referent) if referent.kind() == "pointer_type" => {
                            EvalState::Incomplete(RustOwnershipIncomplete::RawPointer)
                        }
                        Some(_) if reference_is_mutable_bounded(node, charge)? => EvalState::Move,
                        Some(_) => EvalState::Copy,
                    }),
                    "pointer_type" => TypeEvaluation::Leaf(EvalState::Incomplete(
                        RustOwnershipIncomplete::RawPointer,
                    )),
                    "type_identifier"
                    | "identifier"
                    | "scoped_type_identifier"
                    | "scoped_identifier" => expand(node, charge)?.unwrap_or_else(|| {
                        TypeEvaluation::Leaf(self.classify_nominal_reference(node))
                    }),
                    "generic_type" => expand(node, charge)?.unwrap_or(TypeEvaluation::Leaf(
                        EvalState::Incomplete(RustOwnershipIncomplete::GenericObligation),
                    )),
                    _ => TypeEvaluation::Leaf(EvalState::Incomplete(
                        RustOwnershipIncomplete::UnsupportedType,
                    )),
                }
            };
            match plan {
                TypeEvaluation::Leaf(state) => {
                    active.remove(&key);
                    values.insert(key, state);
                }
                plan => {
                    let child_count = match &plan {
                        TypeEvaluation::Alias(_) | TypeEvaluation::Option(_) => 1,
                        TypeEvaluation::Aggregate(children) => children.len(),
                        TypeEvaluation::Leaf(_) => unreachable!(),
                    };
                    charge(child_count)?;
                    let children = match &plan {
                        TypeEvaluation::Alias(child) | TypeEvaluation::Option(child) => {
                            vec![*child]
                        }
                        TypeEvaluation::Aggregate(children) => children.clone(),
                        TypeEvaluation::Leaf(_) => unreachable!(),
                    };
                    plans.insert(key, plan);
                    charge(1)?;
                    stack.push((node, true));
                    for child in children.into_iter().rev() {
                        charge(1)?;
                        stack.push((child, false));
                    }
                }
            }
        }
        charge(0)?;
        Ok(values[&type_node.id()])
    }

    fn classify_nominal_reference(&self, type_node: Node<'tree>) -> EvalState {
        if !valid_path_shape(type_node) {
            return EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        }
        let index = match self.unique_nominal_candidate_index(type_node) {
            Ok(index) => index,
            Err(reason) => return EvalState::Incomplete(reason),
        };
        match self
            .states
            .get(&index)
            .copied()
            .expect("nominal candidate is indexed")
        {
            NominalState::Pending => EvalState::Pending,
            NominalState::Copy => EvalState::Copy,
            NominalState::Move => EvalState::Move,
            NominalState::Incomplete(reason) => EvalState::Incomplete(reason),
        }
    }

    fn nominal_identity_index(
        &self,
        type_node: Node<'tree>,
    ) -> Result<usize, RustOwnershipIncomplete> {
        if !valid_path_shape(type_node) || contains_generic(type_node) {
            return Err(RustOwnershipIncomplete::GenericObligation);
        }
        let index = self.unique_nominal_candidate_index(type_node)?;
        match self
            .states
            .get(&index)
            .copied()
            .expect("nominal candidate is indexed")
        {
            NominalState::Pending => Err(RustOwnershipIncomplete::CyclicNominal),
            NominalState::Incomplete(reason) => Err(reason),
            NominalState::Copy | NominalState::Move => Ok(index),
        }
    }

    fn unique_nominal_candidate_index(
        &self,
        type_node: Node<'tree>,
    ) -> Result<usize, RustOwnershipIncomplete> {
        let path_nodes =
            rust_path_segments(type_node).ok_or(RustOwnershipIncomplete::UnresolvedPath)?;
        let path = path_nodes
            .iter()
            .map(|segment| rust_node_text(*segment, self.source).to_string())
            .collect::<Vec<_>>();
        let module_path = self.lexical_module_path(type_node);
        let candidates = self
            .resolve_nominal_candidates(&module_path, &path)
            .ok_or(RustOwnershipIncomplete::UnresolvedPath)?;
        if candidates.len() != 1 {
            return Err(RustOwnershipIncomplete::AmbiguousIdentity);
        }
        Ok(candidates[0])
    }

    fn resolve_nominal_candidates(
        &self,
        module_path: &[String],
        path: &[String],
    ) -> Option<Vec<usize>> {
        if path.is_empty() {
            return None;
        }
        if path[0] == "crate" {
            return self.by_path.get(&path[1..]).cloned();
        }

        let mut aliases = Vec::new();
        for import in &self.imports {
            if import.wildcard || import.local_name != path[0] {
                continue;
            }
            if is_lexically_visible(module_path, &import.module_path) {
                aliases.push(import);
            }
        }
        if aliases.len() > 1 {
            return Some(Vec::new());
        }
        if let Some(alias) = aliases.first() {
            let mut target = resolve_relative_path(&alias.module_path, &alias.target_path)?;
            target.extend(path.iter().skip(1).cloned());
            return self.by_path.get(&target).cloned();
        }

        let mut ancestor_count = module_path.len();
        loop {
            let mut candidate = module_path[..ancestor_count].to_vec();
            candidate.extend(path.iter().cloned());
            if let Some(found) = self.by_path.get(&candidate) {
                return Some(found.clone());
            }
            if ancestor_count == 0 {
                break;
            }
            ancestor_count -= 1;
        }
        None
    }

    fn evaluate_declaration(&self, declaration_index: usize) -> NominalState {
        let declaration = &self.declarations[declaration_index];
        if declaration.generic {
            return NominalState::Incomplete(RustOwnershipIncomplete::GenericObligation);
        }
        if declaration.malformed_payload {
            return NominalState::Incomplete(RustOwnershipIncomplete::MissingType);
        }
        let builtin_root_shadowed = self
            .name_is_shadowed(&declaration.identity.module_path, "core")
            || self.name_is_shadowed(&declaration.identity.module_path, "std");
        if declaration
            .evidence
            .has_invalid_copy_claim(builtin_root_shadowed)
        {
            return NominalState::Incomplete(RustOwnershipIncomplete::WrongTraitIdentity);
        }
        if declaration.evidence.drop_count != 0 || declaration.evidence.negative_copy {
            return NominalState::Move;
        }

        let mut saw_pending = false;
        let mut saw_move = false;
        for payload in &declaration.payload_types {
            match self.classify_type_state(*payload) {
                EvalState::Copy => {}
                EvalState::Move => saw_move = true,
                EvalState::Pending => saw_pending = true,
                EvalState::Incomplete(reason) => return NominalState::Incomplete(reason),
            }
        }
        if saw_move {
            return NominalState::Move;
        }
        if saw_pending {
            return NominalState::Pending;
        }
        if declaration.evidence.has_copy_proof(builtin_root_shadowed) {
            NominalState::Copy
        } else {
            // A Copy implementation may be in another same-crate module or
            // file.  Without an exact non-Copy payload or local negative/Drop
            // evidence, this producer cannot call the type a move.
            NominalState::Incomplete(RustOwnershipIncomplete::UnsupportedType)
        }
    }

    fn apply_impl(&mut self, implementation: PendingImpl<'tree>) {
        if implementation.generic || has_macro_ancestor(implementation.node) {
            return;
        }
        if !valid_path_shape(implementation.target_node)
            || contains_generic(implementation.target_node)
        {
            return;
        }
        let Some(target_path_nodes) = rust_path_segments(implementation.target_node) else {
            return;
        };
        let target_path = target_path_nodes
            .iter()
            .map(|segment| rust_node_text(*segment, self.source).to_string())
            .collect::<Vec<_>>();
        let Some(candidates) =
            self.resolve_nominal_candidates(&implementation.module_path, &target_path)
        else {
            return;
        };
        if candidates.len() != 1 {
            for candidate in candidates {
                self.declarations[candidate].evidence.wrong_builtin_count += 1;
            }
            return;
        }
        let declaration_index = candidates[0];
        let Some(trait_node) = implementation.trait_node else {
            return;
        };
        let Some(trait_kind) = builtin_trait_kind(
            trait_node,
            self.source,
            &implementation.module_path,
            &self.shadowed_names,
        ) else {
            if path_terminal_is_builtin(trait_node, self.source) {
                self.declarations[declaration_index]
                    .evidence
                    .wrong_builtin_count += 1;
            }
            return;
        };
        if implementation.negative {
            if trait_kind == BuiltinTrait::Copy {
                self.declarations[declaration_index].evidence.negative_copy = true;
            }
            return;
        }
        let drop_method = if trait_kind == BuiltinTrait::Drop {
            let methods = implementation
                .node
                .child_by_field_name("body")
                .map(named_children)
                .unwrap_or_default()
                .into_iter()
                .filter(|member| {
                    member.kind() == "function_item"
                        && member
                            .child_by_field_name("name")
                            .is_some_and(|name| rust_node_text(name, self.source) == "drop")
                })
                .collect::<Vec<_>>();
            (methods.len() == 1).then(|| methods[0])
        } else {
            None
        };
        let declaration = &mut self.declarations[declaration_index];
        match trait_kind {
            BuiltinTrait::Copy => declaration.evidence.copy_count += 1,
            BuiltinTrait::Clone => declaration.evidence.clone_count += 1,
            BuiltinTrait::Drop => {
                declaration.evidence.drop_count += 1;
                match (declaration.drop_impl_method, drop_method) {
                    (None, Some(method)) if !declaration.drop_impl_ambiguous => {
                        declaration.drop_impl_method = Some(method);
                    }
                    _ => declaration.drop_impl_ambiguous = true,
                }
            }
        }
    }

    fn name_is_shadowed(&self, module_path: &[String], name: &str) -> bool {
        name_is_shadowed(&self.shadowed_names, module_path, name)
    }
}

impl EvalState {
    fn into_public(self) -> RustOwnershipClass {
        match self {
            Self::Copy => RustOwnershipClass::AggregateCopy,
            Self::Move => RustOwnershipClass::Move,
            Self::Pending => RustOwnershipClass::Incomplete(RustOwnershipIncomplete::CyclicNominal),
            Self::Incomplete(reason) => RustOwnershipClass::Incomplete(reason),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuiltinTrait {
    Copy,
    Clone,
    Drop,
}

#[derive(Clone, Debug)]
struct LexicalModuleContext {
    parent: Option<usize>,
    name: String,
}

#[derive(Clone, Debug)]
struct ScanFrame<'tree> {
    node: Node<'tree>,
    module_path: Vec<String>,
    module_context: Option<usize>,
    under_macro: bool,
}

fn nominal_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
    module_path: &[String],
    shadowed: &mut HashSet<ShadowedBinding>,
) -> Option<NominalDeclaration<'tree>> {
    let node = unwrap_attributes(node);
    let expected_kind = match node.kind() {
        "struct_item" => "struct",
        "enum_item" => "enum",
        "union_item" => "union",
        "trait_item" | "mod_item" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .map(|name| rust_node_text(name, source))
            {
                shadowed.insert(ShadowedBinding {
                    module_path: module_path.to_vec(),
                    name: name.to_string(),
                });
            }
            return None;
        }
        _ => return None,
    };
    let name = node
        .child_by_field_name("name")
        .map(|name| rust_node_text(name, source).to_string())?;
    shadowed.insert(ShadowedBinding {
        module_path: module_path.to_vec(),
        name: name.clone(),
    });
    let identity = RustNominalIdentity {
        module_path: module_path.to_vec(),
        name,
        source_start: node.start_byte(),
    };
    let (payload_types, malformed_payload) = payload_types(node, expected_kind);
    let struct_drop_fields = (expected_kind == "struct")
        .then(|| struct_drop_fields(node))
        .flatten();
    let evidence = derive_evidence(node, source);
    Some(NominalDeclaration {
        identity,
        payload_types,
        struct_drop_fields,
        generic: node.child_by_field_name("type_parameters").is_some() || has_where_clause(node),
        generic_drop_obligation: has_where_clause(node)
            || node
                .child_by_field_name("type_parameters")
                .is_some_and(|parameters| {
                    named_children(parameters)
                        .into_iter()
                        .any(|parameter| parameter.kind() != "lifetime_parameter")
                }),
        malformed_payload,
        evidence,
        drop_impl_method: None,
        drop_impl_ambiguous: false,
    })
}

fn struct_drop_fields<'tree>(node: Node<'tree>) -> Option<Vec<(Option<Node<'tree>>, Node<'tree>)>> {
    let Some(body) = node.child_by_field_name("body") else {
        return Some(Vec::new());
    };
    match body.kind() {
        "field_declaration_list" => named_children(body)
            .into_iter()
            .filter(|field| field.kind() == "field_declaration")
            .map(|field| {
                Some((
                    field.child_by_field_name("name"),
                    field.child_by_field_name("type")?,
                ))
            })
            .collect(),
        "ordered_field_declaration_list" => named_children(body)
            .into_iter()
            .filter(|node| is_type_node(*node))
            .map(|ty| Some((None, ty)))
            .collect(),
        _ => None,
    }
}

fn payload_types<'tree>(node: Node<'tree>, expected_kind: &str) -> (Vec<Node<'tree>>, bool) {
    let Some(body) = node.child_by_field_name("body") else {
        return (Vec::new(), false);
    };
    let mut result = Vec::new();
    let mut malformed = false;
    if expected_kind == "enum" {
        for variant in named_children(body) {
            if variant.kind() != "enum_variant" {
                continue;
            }
            if let Some(variant_body) = variant.child_by_field_name("body") {
                collect_body_types(variant_body, &mut result, &mut malformed);
            }
        }
    } else {
        collect_body_types(body, &mut result, &mut malformed);
    }
    (result, malformed)
}

fn collect_body_types<'tree>(
    body: Node<'tree>,
    result: &mut Vec<Node<'tree>>,
    malformed: &mut bool,
) {
    match body.kind() {
        "field_declaration_list" => {
            for field in named_children(body) {
                if field.kind() != "field_declaration" {
                    continue;
                }
                if let Some(type_node) = field.child_by_field_name("type") {
                    result.push(type_node);
                } else {
                    *malformed = true;
                }
            }
        }
        "ordered_field_declaration_list" => {
            for child in named_children(body) {
                if is_type_node(child) {
                    result.push(child);
                }
            }
        }
        _ => *malformed = true,
    }
}

fn derive_evidence(node: Node<'_>, source: &str) -> TraitEvidence {
    let mut evidence = TraitEvidence::default();
    let Some(attributes) = crate::resolution::rust_item_effective_attributes(node, source) else {
        return evidence;
    };
    for attribute in attributes {
        let Some(path) = attribute.path.first().copied() else {
            continue;
        };
        if attribute.path.len() == 1
            && path.kind() == "identifier"
            && rust_node_text(path, source) == "derive"
        {
            // A conditional derive is not evidence that the type implements
            // Copy or Clone in every configuration.
            if attribute.from_cfg_attr {
                continue;
            }
            let Some(arguments) = attribute.arguments else {
                evidence.malformed_derive = true;
                continue;
            };
            let Ok(traits) = derive_builtin_traits(arguments, source) else {
                evidence.malformed_derive = true;
                continue;
            };
            for (trait_kind, qualified) in traits {
                match trait_kind {
                    BuiltinTrait::Copy => {
                        evidence.derive_copy = true;
                        evidence.derive_copy_qualified |= qualified;
                    }
                    BuiltinTrait::Clone => {
                        evidence.derive_clone = true;
                        evidence.derive_clone_qualified |= qualified;
                    }
                    BuiltinTrait::Drop => evidence.malformed_derive = true,
                }
            }
        }
    }
    evidence
}

/// Read derive paths from the token tree's sibling structure. Tree-sitter
/// retains each identifier and `::` token even though it does not wrap the
/// path in a scoped-identifier node; no source-text parser is needed.
fn derive_builtin_traits(
    arguments: Node<'_>,
    source: &str,
) -> Result<Vec<(BuiltinTrait, bool)>, ()> {
    if arguments.kind() != "token_tree" || arguments.child_count() < 2 {
        return Err(());
    }
    let mut cursor = arguments.walk();
    let children = arguments.children(&mut cursor).collect::<Vec<_>>();
    let mut index = 1;
    let end = children.len() - 1;
    let mut traits = Vec::new();
    while index < end {
        if children[index].kind() == "," {
            index += 1;
            continue;
        }
        if children[index].kind() != "identifier" {
            return Err(());
        }
        let mut segments = vec![rust_node_text(children[index], source)];
        index += 1;
        while index < end && children[index].kind() == "::" {
            let Some(segment) = children
                .get(index + 1)
                .filter(|segment| index + 1 < end && segment.kind() == "identifier")
            else {
                return Err(());
            };
            segments.push(rust_node_text(*segment, source));
            index += 2;
        }
        if let Some(kind) = builtin_trait_names_kind(&segments) {
            traits.push((kind, segments.len() > 1));
        } else if segments.last().is_some_and(|name| is_builtin_name(name)) {
            return Err(());
        }
        if index < end && children[index].kind() != "," {
            return Err(());
        }
    }
    Ok(traits)
}

fn collect_imports<F, E>(
    node: Node<'_>,
    source: &str,
    module_path: &[String],
    imports: &mut Vec<ImportBinding>,
    shadowed: &mut HashSet<ShadowedBinding>,
    charge: &mut F,
) -> Result<(), E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    for leaf in crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
        node,
        source,
        &mut *charge,
    )? {
        charge(1)?;
        let import = leaf.import;
        charge(module_path.len())?;
        for segment in import.path() {
            charge(1)?;
            charge(segment.len())?;
        }
        match import.binding_name() {
            RustImportBindingName::Glob => {
                for name in ["Copy", "Clone", "Drop"] {
                    charge(1)?;
                    shadowed.insert(ShadowedBinding {
                        module_path: module_path.to_vec(),
                        name: name.to_string(),
                    });
                }
                imports.push(ImportBinding {
                    module_path: module_path.to_vec(),
                    local_name: String::new(),
                    target_path: import.path().to_vec(),
                    wildcard: true,
                });
            }
            RustImportBindingName::Named(name) => {
                if name == "_" {
                    continue;
                }
                charge(name.len())?;
                shadowed.insert(ShadowedBinding {
                    module_path: module_path.to_vec(),
                    name: name.to_string(),
                });
                imports.push(ImportBinding {
                    module_path: module_path.to_vec(),
                    local_name: name.to_string(),
                    target_path: import.path().to_vec(),
                    wildcard: false,
                });
            }
            RustImportBindingName::Unnamed => {}
        }
    }
    charge(0)?;
    Ok(())
}

fn builtin_trait_kind(
    node: Node<'_>,
    source: &str,
    module_path: &[String],
    shadowed: &HashSet<ShadowedBinding>,
) -> Option<BuiltinTrait> {
    let kind = builtin_trait_path_kind(node, source)?;
    let names = rust_path_segments(node)?
        .iter()
        .map(|segment| rust_node_text(*segment, source))
        .collect::<Vec<_>>();
    if names.len() == 1 {
        return None;
    }
    let rooted = rust_path_is_leading_absolute(node);
    (rooted || !name_is_shadowed(shadowed, module_path, names[0])).then_some(kind)
}

fn builtin_trait_path_kind(node: Node<'_>, source: &str) -> Option<BuiltinTrait> {
    if !valid_path_shape(node) || contains_generic(node) {
        return None;
    }
    let nodes = rust_path_segments(node)?;
    let names = nodes
        .iter()
        .map(|segment| rust_node_text(*segment, source))
        .collect::<Vec<_>>();
    builtin_trait_names_kind(&names)
}

fn builtin_trait_names_kind(names: &[&str]) -> Option<BuiltinTrait> {
    let last = *names.last()?;
    let kind = match last {
        "Copy" => BuiltinTrait::Copy,
        "Clone" => BuiltinTrait::Clone,
        "Drop" => BuiltinTrait::Drop,
        _ => return None,
    };
    if names.len() == 1 {
        return Some(kind);
    }
    let expected = match kind {
        BuiltinTrait::Copy => ["marker", last],
        BuiltinTrait::Clone => ["clone", last],
        BuiltinTrait::Drop => ["ops", last],
    };
    if names.len() == 3
        && (names[0] == "core" || names[0] == "std")
        && names[1] == expected[0]
        && names[2] == expected[1]
    {
        Some(kind)
    } else {
        None
    }
}

fn name_is_shadowed(
    shadowed: &HashSet<ShadowedBinding>,
    module_path: &[String],
    name: &str,
) -> bool {
    shadowed.iter().any(|binding| {
        binding.name == name && is_lexically_visible(module_path, &binding.module_path)
    })
}

fn path_terminal_is_builtin(node: Node<'_>, source: &str) -> bool {
    rust_path_segments(node)
        .and_then(|segments| segments.last().copied())
        .is_some_and(|last| is_builtin_name(rust_node_text(last, source)))
}

fn aggregate_result(states: impl Iterator<Item = EvalState>) -> EvalState {
    let mut saw_pending = false;
    for state in states {
        match state {
            EvalState::Copy => {}
            EvalState::Move => return EvalState::Move,
            EvalState::Pending => saw_pending = true,
            EvalState::Incomplete(reason) => return EvalState::Incomplete(reason),
        }
    }
    if saw_pending {
        EvalState::Pending
    } else {
        EvalState::Copy
    }
}

fn is_builtin_name(name: &str) -> bool {
    matches!(name, "Copy" | "Clone" | "Drop")
}

fn is_copy_primitive(node: Node<'_>, source: &str) -> bool {
    is_integer_primitive(node, source)
        || is_float_primitive(node, source)
        || is_named_primitive(node, source, "bool")
        || is_named_primitive(node, source, "char")
}

fn is_integer_primitive(node: Node<'_>, source: &str) -> bool {
    node.kind() == "primitive_type"
        && matches!(
            rust_node_text(node, source),
            "u8" | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
        )
}

fn is_float_primitive(node: Node<'_>, source: &str) -> bool {
    node.kind() == "primitive_type" && matches!(rust_node_text(node, source), "f32" | "f64")
}

fn is_named_primitive(node: Node<'_>, source: &str, name: &str) -> bool {
    node.kind() == "primitive_type" && rust_node_text(node, source) == name
}

fn is_type_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "primitive_type"
            | "unit_type"
            | "never_type"
            | "reference_type"
            | "pointer_type"
            | "array_type"
            | "slice_type"
            | "tuple_type"
            | "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "generic_type"
    )
}

fn declaration_path<'tree>(declaration: &NominalDeclaration<'tree>) -> Vec<String> {
    let mut path = declaration.identity.module_path.clone();
    path.push(declaration.identity.name.clone());
    path
}

fn has_where_clause(node: Node<'_>) -> bool {
    has_where_clause_bounded(node, &mut |_| Ok::<_, std::convert::Infallible>(()))
        .expect("infallible legacy where-clause inspection")
}

fn has_named_child_bounded<F, E>(node: Node<'_>, kind: &str, charge: &mut F) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        charge(1)?;
        if child.kind() == kind {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_where_clause_bounded<F, E>(node: Node<'_>, charge: &mut F) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    has_named_child_bounded(node, "where_clause", charge)
}

pub(crate) fn has_macro_ancestor(node: Node<'_>) -> bool {
    has_macro_ancestor_bounded(node, &mut |_| Ok::<_, std::convert::Infallible>(()))
        .expect("infallible legacy macro ancestry")
}

fn has_macro_ancestor_bounded<F, E>(mut node: Node<'_>, charge: &mut F) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    loop {
        charge(1)?;
        let Some(parent) = node.parent() else {
            return Ok(false);
        };
        if matches!(parent.kind(), "macro_invocation" | "macro_definition") {
            return Ok(true);
        }
        node = parent;
    }
}

fn has_unsafe_ancestor(node: Node<'_>) -> bool {
    has_unsafe_ancestor_bounded(node, &mut |_| Ok::<_, std::convert::Infallible>(()))
        .expect("infallible legacy unsafe ancestry")
}

fn has_unsafe_modifier_bounded<F, E>(node: Node<'_>, charge: &mut F) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        charge(1)?;
        if child.kind() == "unsafe" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_unsafe_ancestor_bounded<F, E>(mut node: Node<'_>, charge: &mut F) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    loop {
        charge(1)?;
        let Some(parent) = node.parent() else {
            return Ok(false);
        };
        if matches!(parent.kind(), "unsafe_block" | "unsafe_item") {
            return Ok(true);
        }
        if parent.kind() == "function_modifiers" && has_unsafe_modifier_bounded(parent, charge)? {
            return Ok(true);
        }
        if matches!(parent.kind(), "function_item" | "function_signature_item") {
            let mut cursor = parent.walk();
            for child in parent.named_children(&mut cursor) {
                charge(1)?;
                if child.kind() == "function_modifiers"
                    && has_unsafe_modifier_bounded(child, charge)?
                {
                    return Ok(true);
                }
            }
        }
        node = parent;
    }
}

fn contains_generic(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "generic_type" || current.kind() == "generic_type_with_turbofish" {
            return true;
        }
        stack.extend(named_children(current));
    }
    false
}

fn valid_path_shape(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "identifier" | "type_identifier" | "self" | "super" | "crate" => {}
            "scoped_identifier" | "scoped_type_identifier" => {
                if !current
                    .child_by_field_name("name")
                    .is_some_and(|name| matches!(name.kind(), "identifier" | "type_identifier"))
                {
                    return false;
                }
                if let Some(path) = current.child_by_field_name("path") {
                    pending.push(path);
                }
            }
            _ => return false,
        }
    }
    true
}

fn reference_referent(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "reference_type").then(|| node.child_by_field_name("type"))?
}

fn reference_is_mutable(node: Node<'_>) -> bool {
    reference_is_mutable_bounded(node, &mut |_| Ok::<_, std::convert::Infallible>(()))
        .expect("infallible legacy reference mutability")
}

fn reference_is_mutable_bounded<F, E>(node: Node<'_>, charge: &mut F) -> Result<bool, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    Ok(node.kind() == "reference_type"
        && has_named_child_bounded(node, "mutable_specifier", charge)?)
}

fn has_mutable_reference_specifier(node: Node<'_>) -> bool {
    has_named_child_bounded(node, "mutable_specifier", &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .expect("infallible legacy mutable specifier")
}

fn classify_reference_type_bounded<F, E>(
    node: Node<'_>,
    charge: &mut F,
) -> Result<RustOwnershipClass, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    assert_eq!(node.kind(), "reference_type");
    charge(1)?;
    let class =
        if reference_referent(node).is_some_and(|referent| referent.kind() == "pointer_type") {
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::RawPointer)
        } else if reference_is_mutable_bounded(node, charge)? {
            RustOwnershipClass::MutableReference
        } else {
            RustOwnershipClass::SharedReference
        };
    charge(0)?;
    Ok(class)
}

fn sequence_element(node: Node<'_>) -> Option<Node<'_>> {
    matches!(node.kind(), "array_type" | "slice_type")
        .then(|| node.child_by_field_name("element"))?
}

fn is_lexically_visible(current: &[String], binding_module: &[String]) -> bool {
    current.starts_with(binding_module)
}

fn resolve_relative_path(base: &[String], path: &[String]) -> Option<Vec<String>> {
    let first = path.first()?;
    if first == "crate" {
        return Some(path[1..].to_vec());
    }
    let mut result = base.to_vec();
    let mut index = 0;
    if first == "self" {
        index = 1;
    } else {
        while index < path.len() && path[index] == "super" {
            result.pop();
            index += 1;
        }
        if index == 0 {
            result.extend(path.iter().cloned());
            return Some(result);
        }
    }
    result.extend(path.iter().skip(index).cloned());
    Some(result)
}

fn resolve_standard_import_path(base: &[String], path: &[String]) -> Vec<String> {
    if path.first().is_some_and(|first| is_standard_root(first)) {
        path.to_vec()
    } else {
        resolve_relative_path(base, path).unwrap_or_else(|| path.to_vec())
    }
}

fn is_standard_root(name: &str) -> bool {
    matches!(name, "alloc" | "core" | "std")
}

fn is_standard_prelude_path(expected: &[&str], names: &[String]) -> bool {
    match expected {
        ["alloc" | "std", "boxed", "Box", suffix @ ..] => {
            names.first().is_some_and(|name| name == "Box")
                && names
                    .iter()
                    .skip(1)
                    .map(String::as_str)
                    .eq(suffix.iter().copied())
        }
        ["alloc" | "std", "vec", "Vec", suffix @ ..] => {
            names.first().is_some_and(|name| name == "Vec")
                && names
                    .iter()
                    .skip(1)
                    .map(String::as_str)
                    .eq(suffix.iter().copied())
        }
        ["alloc" | "std", "string", "String", suffix @ ..] => {
            names.first().is_some_and(|name| name == "String")
                && names
                    .iter()
                    .skip(1)
                    .map(String::as_str)
                    .eq(suffix.iter().copied())
        }
        [
            "core" | "std",
            "option",
            item @ ("Option" | "Some" | "None"),
            suffix @ ..,
        ] => {
            names.first().is_some_and(|name| name == item)
                && names
                    .iter()
                    .skip(1)
                    .map(String::as_str)
                    .eq(suffix.iter().copied())
        }
        ["core" | "std", "result", "Result", suffix @ ..] => {
            names.first().is_some_and(|name| name == "Result")
                && names
                    .iter()
                    .skip(1)
                    .map(String::as_str)
                    .eq(suffix.iter().copied())
        }
        ["core" | "std", "mem", "drop"] => names == ["drop"],
        ["core" | "std", "panic", "panic"] => names == ["panic"],
        _ => false,
    }
}

/// The value operand of `&`/`&mut`; the mutable specifier is deliberately not
/// returned as an operand.  This is the AST-backed fix for the old
/// first-named-child bug (`&mut *source`).
pub fn rust_reference_expression_value(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "reference_expression").then(|| node.child_by_field_name("value"))?
}

/// The referent type of `&T` or `&mut T`.
pub fn rust_reference_type_referent(node: Node<'_>) -> Option<Node<'_>> {
    reference_referent(node)
}

/// Whether a reference type or reference expression is mutable.
pub fn rust_reference_is_mutable(node: Node<'_>) -> bool {
    (node.kind() == "reference_type" || node.kind() == "reference_expression")
        && has_mutable_reference_specifier(node)
}

/// Whether a node is nested in an unsafe block, item, or function.
pub fn rust_node_is_in_unsafe_context(node: Node<'_>) -> bool {
    has_unsafe_ancestor(node)
}

/// The operand of an exact builtin dereference expression (`*value`).
pub fn rust_dereference_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "unary_expression"
        || node.child(0).is_none_or(|operator| operator.kind() != "*")
    {
        return None;
    }
    node.named_child(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::parse_rust as parse;

    fn all_type_nodes<'tree>(root: Node<'tree>) -> Vec<Node<'tree>> {
        let mut result = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if is_type_node(node) {
                result.push(node);
            }
            stack.extend(named_children(node));
        }
        result
    }

    fn type_named<'tree>(root: Node<'tree>, source: &str, expected: &str) -> Node<'tree> {
        all_type_nodes(root)
            .into_iter()
            .find(|node| rust_node_text(*node, source) == expected)
            .unwrap_or_else(|| panic!("type node {expected:?} not found"))
    }

    #[test]
    fn mutable_reference_payload_prevents_an_aggregate_copy_proof() {
        let source = "#[derive(core::marker::Copy, core::clone::Clone)] struct NotCopy(&'static mut u8); fn f(value: NotCopy) {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_ne!(
            index.classify_type(type_named(tree.root_node(), source, "NotCopy")),
            RustOwnershipClass::AggregateCopy
        );
    }

    #[test]
    fn requires_exact_copy_and_clone_evidence_and_handles_drop() {
        let source = "#[derive(core::marker::Copy, core::clone::Clone)] struct Good(u8);\nstruct Plain(u8);\nstruct Dropped(u8);\nimpl core::ops::Drop for Dropped {}\nstruct Negative(u8);\nimpl !core::marker::Copy for Negative {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Good")),
            RustOwnershipClass::AggregateCopy
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Plain")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType)
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Dropped")),
            RustOwnershipClass::Move
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Negative")),
            RustOwnershipClass::Move
        );
    }

    #[test]
    fn rejects_generic_raw_wrong_identity_and_ambiguous_types() {
        let source = "struct A<T>(T);\nstruct S(u8);\nstruct S(u8);\nimpl foo::Copy for S {}\nfn f(a: A<u8>, p: *const u8) {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert!(matches!(
            index.classify_type(type_named(tree.root_node(), source, "A<u8>")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::GenericObligation)
        ));
        assert!(matches!(
            index.classify_type(type_named(tree.root_node(), source, "*const u8")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::RawPointer)
        ));
        assert!(matches!(
            index.classify_type(type_named(tree.root_node(), source, "S")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::AmbiguousIdentity)
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4975: unsafe type mentions suppressed declaration-based destructor proofs"
    )]
    fn destructor_classification_preserves_unsafe_transfer_and_macro_boundaries() {
        let source = "#[derive(core::marker::Copy, core::clone::Clone)] struct Pair(u32); unsafe fn f(value: Pair, unknown: Missing) {} opaque!(Pair);";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let ty = all_type_nodes(tree.root_node())
            .into_iter()
            .find(|node| rust_node_text(*node, source) == "Pair" && has_unsafe_ancestor(*node))
            .expect("unsafe parameter type");
        assert_eq!(
            index.classify_type(ty),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType)
        );
        assert_eq!(
            index.classify_nominal_type_for_drop(ty),
            RustOwnershipClass::AggregateCopy
        );
        assert_eq!(
            index.classify_nominal_type_for_drop(type_named(tree.root_node(), source, "Missing")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnresolvedPath)
        );
        let mut stack = vec![tree.root_node()];
        let macro_type = loop {
            let node = stack.pop().expect("macro argument exists");
            if has_macro_ancestor(node) && rust_node_text(node, source) == "Pair" {
                break node;
            }
            stack.extend(named_children(node));
        };
        assert_eq!(
            index.classify_nominal_type_for_drop(macro_type),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MacroExpansion)
        );
    }

    #[test]
    fn keeps_unsafe_contexts_incomplete() {
        let source = "unsafe fn f(value: u32) -> u32 { value } fn g(value: u32) { unsafe { let copied = value; } }\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let unsafe_type = all_type_nodes(tree.root_node())
            .into_iter()
            .find(|node| {
                rust_node_text(*node, source) == "u32" && rust_node_is_in_unsafe_context(*node)
            })
            .expect("unsafe function type");
        assert_eq!(
            index.classify_type(unsafe_type),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType)
        );
        let unsafe_value = {
            let mut stack = vec![tree.root_node()];
            loop {
                let node = stack.pop().expect("unsafe value expression");
                if node.kind() == "identifier"
                    && rust_node_text(node, source) == "value"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "let_declaration")
                {
                    break node;
                }
                stack.extend(named_children(node));
            }
        };
        assert!(rust_node_is_in_unsafe_context(unsafe_value));
    }

    #[test]
    fn absolute_builtin_trait_path_survives_shadowing_but_prelude_does_not() {
        let source = "mod Copy {}\n#[derive(core::marker::Copy, core::clone::Clone)]\nstruct Qualified(u8);\n#[derive(Copy, Clone)]\nstruct Shadowed(u8);\nstruct Good(u8);\nimpl core::marker::Copy for Good {}\nimpl core::clone::Clone for Good {}\nstruct Bad(u8);\nimpl Copy for Bad {}\nimpl Clone for Bad {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Qualified")),
            RustOwnershipClass::AggregateCopy
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Shadowed")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::WrongTraitIdentity)
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Good")),
            RustOwnershipClass::AggregateCopy
        );
        assert!(matches!(
            index.classify_type(type_named(tree.root_node(), source, "Bad")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::WrongTraitIdentity)
        ));

        let source = "struct Spelled(u8);\nimpl Copy for Spelled {}\nimpl Clone for Spelled {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Spelled")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::WrongTraitIdentity)
        );
    }

    #[test]
    fn resolves_standard_pointer_paths_through_exact_imports_and_shadowing() {
        let source = "use core::ptr as raw; use std::boxed::Box as HeapBox; struct LocalBox(u8); fn f(pointer: *mut u8) { let _ = raw::read(pointer); let _ = HeapBox::from_raw(pointer); let _ = Box::into_raw(pointer); } mod ptr { fn read() {} } fn shadowed() { ptr::read(); }";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut read_path = None;
        let mut box_path = None;
        let mut prelude_box_path = None;
        let mut local_path = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression"
                && let Some(function) = node.child_by_field_name("function")
            {
                match rust_node_text(function, source) {
                    "raw::read" => read_path = Some(function),
                    "HeapBox::from_raw" => box_path = Some(function),
                    "Box::into_raw" => prelude_box_path = Some(function),
                    "ptr::read" => local_path = Some(function),
                    _ => {}
                }
            }
            stack.extend(named_children(node));
        }
        assert!(index.resolves_standard_path(
            read_path.expect("imported pointer read call"),
            &["core", "ptr", "read"]
        ));
        assert!(index.resolves_standard_path(
            box_path.expect("aliased Box constructor"),
            &["std", "boxed", "Box", "from_raw"]
        ));
        assert!(index.resolves_standard_path(
            prelude_box_path.expect("prelude Box constructor"),
            &["std", "boxed", "Box", "into_raw"]
        ));
        assert!(!index.resolves_standard_path(
            local_path.expect("local ptr module call"),
            &["core", "ptr", "read"]
        ));

        let source = "struct Box(u8); fn f() { let _value: Box = Box(0); }";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut box_type = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "type_identifier" && rust_node_text(node, source) == "Box" {
                box_type = Some(node);
            }
            stack.extend(named_children(node));
        }
        assert!(!index.resolves_standard_path(
            box_type.expect("shadowed Box type"),
            &["std", "boxed", "Box"]
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4848: standard path lowering repeated tree-sitter parent searches per call"
    )]
    fn resolves_many_standard_paths_from_nested_module_contexts() {
        let module_depth = 24;
        let call_count = 48;
        let calls = "core::mem::drop(());".repeat(call_count);
        let mut source = format!("fn f() {{ {calls} }}");
        for depth in (0..module_depth).rev() {
            source = format!("mod m{depth} {{ {source} }}");
        }

        let tree = parse(&source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), &source, |_| Ok::<_, ()>(())).unwrap();
        let mut paths = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression"
                && let Some(function) = node.child_by_field_name("function")
            {
                paths.push(function);
            }
            stack.extend(named_children(node));
        }
        assert_eq!(paths.len(), call_count);

        for path in paths {
            assert!(index.resolves_standard_path(path, &["core", "mem", "drop"]));
        }
        assert_eq!(
            index.lexical_module_context_steps.load(Ordering::Relaxed),
            call_count * module_depth
        );
    }

    #[test]
    fn resolves_only_the_exact_local_drop_impl_body() {
        let source = "struct Owned; impl core::ops::Drop for Owned { fn drop(&mut self) {} } fn f(value: Owned) {}";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let ty = type_named(tree.root_node(), source, "Owned");
        let method = index
            .drop_impl_method_for_type(ty)
            .expect("exact Drop type")
            .expect("Drop impl method");
        assert_eq!(method.kind(), "function_item");
        assert_eq!(
            method
                .child_by_field_name("name")
                .map(|name| rust_node_text(name, source)),
            Some("drop")
        );

        let source =
            "struct Owned; mod custom { pub trait Drop {} } impl custom::Drop for Owned {}";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            index.drop_impl_method_for_type(type_named(tree.root_node(), source, "Owned")),
            Ok(None)
        );

        let source = "struct Field; struct Owner { first: Field, second: u8 }";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let fields = index
            .drop_fields_for_type(type_named(tree.root_node(), source, "Owner"))
            .expect("nongeneric local struct fields");
        assert_eq!(fields.len(), 2);
        assert_eq!(
            fields[0].0.map(|name| rust_node_text(name, source)),
            Some("first")
        );
        assert_eq!(
            fields[1].0.map(|name| rust_node_text(name, source)),
            Some("second")
        );
    }

    #[test]
    fn proves_reference_reborrow_and_array_slice_unsizing_structurally() {
        let source = "fn f(a: &[u8; 2], b: &[u8], c: &mut u8, d: &u8) {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let array_reference = type_named(tree.root_node(), source, "&[u8; 2]");
        let slice_reference = type_named(tree.root_node(), source, "&[u8]");
        let mutable_reference = type_named(tree.root_node(), source, "&mut u8");
        let shared_reference = type_named(tree.root_node(), source, "&u8");
        assert_eq!(
            index.classify_reference_coercion(array_reference, slice_reference),
            RustReferenceCoercion::ArrayReferenceToSlice
        );
        assert_eq!(
            index.classify_reference_coercion(mutable_reference, shared_reference),
            RustReferenceCoercion::MutableToSharedReborrow
        );
        assert!(
            index
                .exact_type_equivalence(shared_reference, shared_reference)
                .expect("reference type is structurally supported")
        );
    }

    #[test]
    fn reference_expression_operand_excludes_mutability_and_exposes_exact_deref() {
        let source = "fn f(source: &mut u8) { let a = &mut *source; let b = &mut source; }\n";
        let tree = parse(source);
        let mut references = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "reference_expression" {
                references.push(node);
            }
            stack.extend(named_children(node));
        }
        references.sort_by_key(Node::start_byte);
        let [dereference_borrow, direct_borrow] = references.as_slice() else {
            panic!("expected the two reference expressions, found {references:#?}");
        };

        let dereference = rust_reference_expression_value(*dereference_borrow)
            .expect("mutable borrow has a value field");
        assert_eq!(rust_node_text(dereference, source), "*source");
        assert_eq!(
            rust_node_text(
                rust_dereference_operand(dereference).expect("builtin dereference operand"),
                source,
            ),
            "source"
        );
        assert_eq!(
            rust_node_text(
                rust_reference_expression_value(*direct_borrow)
                    .expect("near-miss mutable borrow has a value field"),
                source,
            ),
            "source"
        );
    }

    #[test]
    fn nested_trait_shadow_does_not_poison_outer_qualified_derives() {
        let source = "#[derive(core::marker::Copy, core::clone::Clone)] struct Outer(u8); mod nested { trait Copy {} struct Inner(u8); impl Copy for Inner {} } fn f(value: Outer) {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Outer")),
            RustOwnershipClass::AggregateCopy
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "Inner")),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::WrongTraitIdentity)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5911: tuple-let component initialization lacked alias-rebased type and Option Copy proof"
    )]
    fn tuple_components_keep_alias_scope_option_identity_and_stops() {
        // Invalid/cfg-ambiguous type declarations below are intentional
        // refusal controls. Parsing them is not evidence of Rust validity.
        let source = r#"
use core::option::Option as Maybe;
struct NotCopy<T>(T);
type SizeHint = (usize, Option<usize>);
type Pair = (usize, usize);
type Borrow = &'static usize;
type CycleA = CycleB;
type CycleB = CycleA;
fn ordinary() {
    let direct: (usize, usize);
    let pair: Pair;
    let size: SizeHint;
    let optional: Maybe<usize>;
    let nested: Option<Option<usize>>;
    let alias_reference: Borrow;
    let borrowed: &Pair;
    let mutable_payload: Option<&'static mut usize>;
    let unknown_payload: Option<Missing>;
    let inert_is_not_copy: Option<String>;
    let other_generic: Vec<usize>;
    let too_many_arguments: Option<usize, usize>;
    let non_type_argument: Option<3>;
    let cycle: CycleA;
}
fn local_shadow() {
    let forward: Pair;
    type Pair = (usize, bool);
    type Option<T> = NotCopy<T>;
    let rebased: SizeHint;
    let local_option: Option<usize>;
}
fn import_shadow() {
    use core::option::Option as Choice;
    use crate::NotCopy as Choice;
    let ambiguous: Choice<usize>;
}
fn conditional_import() {
    #[cfg(feature = "maybe")]
    use core::option::Option as Conditional;
    let conditional: Conditional<usize>;
}
fn opaque_scope() {
    opaque!();
    let macro_scope: Option<usize>;
}
fn wildcard_scope() {
    use crate::unknown::*;
    let wildcard: Option<usize>;
}
fn generic<Option>(generic_parameter: Option) {}
fn primitive_generic<usize>() {
    let generic_primitive: usize;
    let generic_payload: Option<usize>;
}
fn primitive_shadow() {
    type usize = NotCopy<u8>;
    let shadowed_primitive: usize;
    let shadowed_payload: Option<usize>;
    let rhs_rebased: SizeHint;
}
fn shadow_root() {
    mod core { pub mod option { pub struct Option<T>(T); } }
    use core::option::Option as Wrong;
    let wrong_root: Wrong<usize>;
    let absolute: ::core::option::Option<usize>;
    let absolute_option: ::Option<usize>;
}
mod disabled_owner {
    #![no_implicit_prelude]
    type Pair = (usize, Option<usize>);
    fn probe() { let nested_disabled: Pair; }
}
mod conditional_owner {
    #![cfg(feature = "maybe")]
    fn probe() { let inner_activation: Option<usize>; }
}
fn grouped_imports() {
    use core::option::{Option as FirstChoice, Option as SecondChoice, Option as ThirdChoice};
    let grouped: ThirdChoice<usize>;
}
"#;
        let tree = parse(source);
        let root = tree.root_node();
        let index = RustOwnershipIndex::build(root, source, |_| Ok::<_, ()>(())).unwrap();
        let declared_type = |name: &str| {
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                if matches!(node.kind(), "let_declaration" | "parameter")
                    && node
                        .child_by_field_name("pattern")
                        .is_some_and(|pattern| rust_node_text(pattern, source) == name)
                {
                    return node.child_by_field_name("type").expect("annotated binding");
                }
                stack.extend(named_children(node));
            }
            panic!("missing test binding {name}");
        };
        for name in ["direct", "pair", "size", "rebased", "rhs_rebased"] {
            let ty = declared_type(name);
            let components = index
                .tuple_component_types_bounded(ty, |_| Ok::<_, ()>(()))
                .unwrap()
                .unwrap();
            assert_eq!(components.len(), 2, "{name}");
            assert_eq!(rust_node_text(components[0], source), "usize", "{name}");
            assert_eq!(
                index
                    .classify_type_bounded(ty, |_| Ok::<_, ()>(()))
                    .unwrap(),
                RustOwnershipClass::AggregateCopy,
                "{name}"
            );
            for component in components {
                assert!(
                    matches!(
                        index
                            .classify_type_bounded(component, |_| Ok::<_, ()>(()))
                            .unwrap(),
                        RustOwnershipClass::ScalarCopy | RustOwnershipClass::AggregateCopy
                    ),
                    "{name}"
                );
            }
        }
        let forward = index
            .tuple_component_types_bounded(declared_type("forward"), |_| Ok::<_, ()>(()))
            .unwrap()
            .unwrap();
        assert_eq!(
            rust_node_text(forward[1], source),
            "bool",
            "local item shadows before its declaration"
        );
        for name in ["optional", "nested", "absolute", "grouped"] {
            assert_eq!(
                index
                    .classify_type_bounded(declared_type(name), |_| Ok::<_, ()>(()))
                    .unwrap(),
                RustOwnershipClass::AggregateCopy,
                "{name}"
            );
        }
        for name in ["alias_reference", "borrowed"] {
            assert_eq!(
                index
                    .classify_type_bounded(declared_type(name), |_| Ok::<_, ()>(()))
                    .unwrap(),
                RustOwnershipClass::SharedReference,
                "{name}"
            );
            assert!(
                index
                    .tuple_component_types_bounded(declared_type(name), |_| Ok::<_, ()>(()))
                    .unwrap()
                    .is_err(),
                "{name}"
            );
        }
        for name in [
            "local_option",
            "ambiguous",
            "conditional",
            "generic_parameter",
            "wrong_root",
            "mutable_payload",
            "unknown_payload",
            "inert_is_not_copy",
            "other_generic",
            "absolute_option",
            "nested_disabled",
            "inner_activation",
            "macro_scope",
            "wildcard",
            "too_many_arguments",
            "non_type_argument",
            "generic_primitive",
            "generic_payload",
            "shadowed_primitive",
            "shadowed_payload",
        ] {
            assert!(
                matches!(
                    index
                        .classify_type_bounded(declared_type(name), |_| Ok::<_, ()>(()))
                        .unwrap(),
                    RustOwnershipClass::Incomplete(_)
                ),
                "{name}"
            );
        }
        assert_eq!(
            index
                .tuple_component_types_bounded(declared_type("cycle"), |_| Ok::<_, ()>(()))
                .unwrap(),
            Err(RustOwnershipIncomplete::CyclicNominal)
        );
        let mut charged = 0;
        assert!(
            index
                .tuple_component_types_bounded(declared_type("size"), |work| {
                    charged += work;
                    if charged > 4 { Err(()) } else { Ok(()) }
                })
                .is_err()
        );
        let mut worked = false;
        assert!(
            index
                .classify_type_bounded(declared_type("size"), |work| {
                    if work == 0 && worked {
                        return Err(());
                    }
                    worked |= work != 0;
                    Ok(())
                })
                .is_err(),
            "a terminal stop cannot publish Copy"
        );
        // Nested ownership evaluation revisits ancestry for each component.
        // Interrupt those actual parent walks, rather than only the initial
        // root admission or a later type-head lookup.
        let nested_source = "unsafe fn probe(value: ((((u8,),),),)) {}";
        let nested_tree = parse(nested_source);
        let nested_type = type_named(nested_tree.root_node(), nested_source, "u8");
        let mut macro_work = 0;
        assert_eq!(
            has_macro_ancestor_bounded(nested_type, &mut |work| {
                macro_work += work;
                if macro_work == 3 { Err(()) } else { Ok(()) }
            }),
            Err(())
        );
        assert_eq!(macro_work, 3);
        let mut unsafe_work = 0;
        assert_eq!(
            has_unsafe_ancestor_bounded(nested_type, &mut |work| {
                unsafe_work += work;
                if unsafe_work == 3 { Err(()) } else { Ok(()) }
            }),
            Err(())
        );
        assert_eq!(unsafe_work, 3);
        assert!(has_unsafe_ancestor(nested_type));
        assert!(!has_macro_ancestor(nested_type));

        // Child scans must stop inside the helper, including alias admission
        // and reference payload evaluation after normalized ancestry succeeds.
        let inspection_source = "type Alias = u8; fn refs(value: & /* one */ /* two */ mut u8) {}";
        let inspection_tree = parse(inspection_source);
        let alias = inspection_tree.root_node().named_child(0).expect("alias");
        assert_eq!(alias.kind(), "type_item");
        assert_eq!(
            has_where_clause_bounded(alias, &mut |_| Err::<(), _>(())),
            Err(())
        );
        let reference = type_named(
            inspection_tree.root_node(),
            inspection_source,
            "& /* one */ /* two */ mut u8",
        );
        assert_eq!(
            reference_is_mutable_bounded(reference, &mut |_| Err::<(), _>(())),
            Err(())
        );
        assert_eq!(
            classify_reference_type_bounded(reference, &mut |_| Ok::<_, ()>(())),
            Ok(RustOwnershipClass::MutableReference)
        );
        let mut reference_work = 0;
        assert_eq!(
            classify_reference_type_bounded(reference, &mut |work| {
                reference_work += work;
                if reference_work == 2 { Err(()) } else { Ok(()) }
            }),
            Err(())
        );
        assert_eq!(reference_work, 2);

        // Stop inside the exact path walker, not in ownership ancestry.
        let absolute_type = declared_type("absolute");
        let head = absolute_type
            .child_by_field_name("type")
            .expect("Option constructor");
        let complete_path = rust_path_segments(head).expect("structured core Option path");
        assert_eq!(complete_path.len(), 3);
        let mut path_work = 0;
        assert!(
            rust_path_segments_bounded(head, |work| {
                path_work += work;
                if path_work >= 2 { Err(()) } else { Ok(()) }
            })
            .is_err(),
            "no partially retained path can escape a stop"
        );
        assert_eq!(path_work, 2);

        // The collector's post-owner check precedes its pending use-tree
        // stack. Permit several steps past that check, then interrupt the
        // real prefix/group traversal before it can finish collecting leaves.
        let mut pending = vec![root];
        let grouped_use = loop {
            let node = pending.pop().expect("grouped import fixture");
            if node.kind() == "use_declaration"
                && node
                    .child_by_field_name("argument")
                    .is_some_and(|argument| argument.kind() == "scoped_use_list")
            {
                break node;
            }
            pending.extend(named_children(node));
        };
        let leaves = crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
            grouped_use,
            source,
            |_| Ok::<_, ()>(()),
        )
        .unwrap();
        assert_eq!(leaves.len(), 3);
        assert_eq!(
            leaves
                .iter()
                .map(|leaf| leaf.import.info.alias.as_deref())
                .collect::<Vec<_>>(),
            vec![
                Some("FirstChoice"),
                Some("SecondChoice"),
                Some("ThirdChoice")
            ]
        );
        let mut after_owner_setup = false;
        let mut tree_steps = 0;
        let stopped = crate::imports::rust_imports_with_visibility_from_use_declaration_bounded(
            grouped_use,
            source,
            |work| {
                if work == 0 {
                    after_owner_setup = true;
                }
                if after_owner_setup && work != 0 {
                    tree_steps += 1;
                    if tree_steps == 6 {
                        return Err(());
                    }
                }
                Ok(())
            },
        );
        assert!(after_owner_setup);
        assert_eq!(tree_steps, 6);
        assert!(
            stopped.is_err(),
            "no partial leaf list is a complete import answer"
        );

        let disabled_source = "#![no_implicit_prelude]\nfn f(value: Option<usize>) {}";
        let disabled_tree = parse(disabled_source);
        let disabled_index =
            RustOwnershipIndex::build(disabled_tree.root_node(), disabled_source, |_| {
                Ok::<_, ()>(())
            })
            .unwrap();
        let ty = named_children(disabled_tree.root_node())
            .into_iter()
            .find(|node| node.kind() == "function_item")
            .unwrap()
            .child_by_field_name("parameters")
            .unwrap()
            .named_child(0)
            .unwrap()
            .child_by_field_name("type")
            .unwrap();
        assert!(matches!(
            disabled_index
                .classify_type_bounded(ty, |_| Ok::<_, ()>(()))
                .unwrap(),
            RustOwnershipClass::Incomplete(_)
        ));

        // #5911: Copy component types and a tentative local ID do not prove
        // a bare pattern name binds. In particular, a unit constant can be an
        // irrefutable pattern. These controls exercise the independent scope
        // proof without consulting either ownership or the local inventory.
        let binding_source = r#"
const UNIT: () = ();
static STATIC_UNIT: () = ();
struct Empty;
enum Choice { Zero }
fn unit_control(sh: ((), usize)) { let (UNIT, low) = sh; }
fn variable_control(sh: ((), usize)) { let (unit, mut low) = sh; }
fn rebound(a: usize, b: usize) { let (a, b) = (b, a); }
fn prior_local(sh: ((), usize)) { let unit = (); let (unit, low) = sh; }
fn raw_constant(sh: ((), usize)) { let (r#UNIT, low) = sh; }
fn raw_binding(sh: ((), usize)) { let (r#plain, low) = sh; }
fn forward_const(sh: ((), usize)) {
    let (FORWARD, low) = sh;
    const FORWARD: () = ();
}
fn static_control(sh: ((), usize)) { let (STATIC_UNIT, low) = sh; }
fn constructor_control(sh: (Empty, usize)) { let (Empty, low) = sh; }
fn imported(sh: ((), usize)) {
    use crate::UNIT as Imported;
    let (Imported, low) = sh;
}
fn imported_variant(sh: (Choice, usize)) {
    use crate::Choice::Zero;
    let (Zero, low) = sh;
}
fn wildcard(sh: (Choice, usize)) {
    use crate::Choice::*;
    let (Zero, low) = sh;
}
fn late_wildcard(sh: ((), usize)) {
    let (fresh, low) = sh;
    use crate::unknown::*;
}
fn prelude(sh: (Option<usize>, usize)) { let (None, low) = sh; }
fn generic<const N: usize>(sh: (usize, usize)) { let (N, low) = sh; }
fn conditional(sh: ((), usize)) {
    #[cfg(feature = "maybe")]
    const CONDITIONAL: () = ();
    let (CONDITIONAL, low) = sh;
}
fn macro_scope(sh: ((), usize)) { opaque!(); let (fresh, low) = sh; }
fn late_macro(sh: ((), usize)) { let (fresh, low) = sh; opaque!(); }
mod container {
    const NESTED: () = ();
    fn nested(sh: ((), usize)) { let (NESTED, low) = sh; }
}
struct Owner;
impl Owner {
    fn associated(sh: ((), usize)) { let (fresh, low) = sh; }
}
"#;
        let binding_tree = parse(binding_source);
        let binding_root = binding_tree.root_node();
        let pattern_in = |function: &str, name: &str| {
            let mut pending = vec![binding_root];
            while let Some(node) = pending.pop() {
                if node.kind() == "function_item"
                    && node
                        .child_by_field_name("name")
                        .is_some_and(|node| rust_node_text(node, binding_source) == function)
                {
                    let body = node.child_by_field_name("body").expect("fixture body");
                    for declaration in named_children(body) {
                        if declaration.kind() != "let_declaration" {
                            continue;
                        }
                        let pattern = declaration.child_by_field_name("pattern").unwrap();
                        if pattern.kind() != "tuple_pattern" {
                            continue;
                        }
                        for leaf in named_children(pattern) {
                            if rust_node_text(leaf, binding_source) == name {
                                return leaf;
                            }
                        }
                    }
                    panic!("missing tuple leaf {function}::{name}");
                }
                pending.extend(named_children(node));
            }
            panic!("missing function {function}");
        };
        for (function, name, expected) in [
            ("unit_control", "UNIT", false),
            ("unit_control", "low", true),
            ("variable_control", "unit", true),
            ("variable_control", "mut low", true),
            ("rebound", "a", true),
            ("rebound", "b", true),
            ("prior_local", "unit", true),
            ("raw_constant", "UNIT", false),
            ("raw_binding", "plain", true),
            ("forward_const", "FORWARD", false),
            ("static_control", "STATIC_UNIT", false),
            ("constructor_control", "Empty", false),
            ("imported", "Imported", false),
            ("imported", "low", true),
            ("imported_variant", "Zero", false),
            ("wildcard", "Zero", false),
            ("late_wildcard", "fresh", false),
            ("prelude", "None", false),
            ("generic", "N", false),
            ("conditional", "CONDITIONAL", false),
            ("macro_scope", "fresh", false),
            ("late_macro", "fresh", false),
            ("nested", "NESTED", false),
            ("associated", "fresh", false),
        ] {
            let leaf = pattern_in(function, name);
            assert_eq!(
                crate::lexical_scope::rust_pattern_identifier_binding_bounded(
                    binding_root,
                    binding_source,
                    leaf,
                    &mut |_| Ok::<_, ()>(()),
                ),
                Ok(expected),
                "{function}::{name}",
            );
        }
        let mut_leaf = pattern_in("variable_control", "mut low");
        let mut_name = named_children(mut_leaf)
            .into_iter()
            .find(|node| node.kind() == "identifier")
            .unwrap();
        assert_eq!(
            crate::lexical_scope::rust_pattern_identifier_binding_bounded(
                binding_root,
                binding_source,
                mut_name,
                &mut |_| Ok::<_, ()>(()),
            ),
            Ok(true),
        );

        // Stop at the final observation of an otherwise successful proof, so
        // neither completed scope traversal nor a tentative ID can hide a late
        // cancellation. This necessarily reaches beyond ancestor enumeration.
        let leaf = pattern_in("imported", "low");
        let mut complete_calls = 0;
        assert_eq!(
            crate::lexical_scope::rust_pattern_identifier_binding_bounded(
                binding_root,
                binding_source,
                leaf,
                &mut |_| {
                    complete_calls += 1;
                    Ok::<_, ()>(())
                },
            ),
            Ok(true),
        );
        let mut stopped_calls = 0;
        assert_eq!(
            crate::lexical_scope::rust_pattern_identifier_binding_bounded(
                binding_root,
                binding_source,
                leaf,
                &mut |_| {
                    stopped_calls += 1;
                    if stopped_calls == complete_calls {
                        Err(())
                    } else {
                        Ok(())
                    }
                },
            ),
            Err(()),
        );
        assert_eq!(stopped_calls, complete_calls);
    }

    #[test]
    fn charge_callback_bounds_scan_and_fixed_point() {
        let tree = parse("struct A(u8);");
        let mut charges = 0usize;
        let result = RustOwnershipIndex::build(tree.root_node(), "struct A(u8);", |work| {
            charges += work;
            if charges > 2 { Err(()) } else { Ok(()) }
        });
        assert!(result.is_err());
        assert!(charges > 0);
    }
}
