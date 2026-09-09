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
use crate::graph::ast::{rust_path_is_leading_absolute, rust_path_segments};
use crate::imports::{RustImportBindingName, rust_imports_with_visibility_from_use_declaration};
use std::collections::{HashMap, HashSet};
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
    generic: bool,
    malformed_payload: bool,
    evidence: TraitEvidence,
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
    declarations: Vec<NominalDeclaration<'tree>>,
    by_path: HashMap<Vec<String>, Vec<usize>>,
    imports: Vec<ImportBinding>,
    shadowed_names: HashSet<ShadowedBinding>,
    states: HashMap<usize, NominalState>,
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
        let mut stack = vec![ScanFrame {
            node: root,
            module_path: Vec::new(),
            under_macro: false,
        }];

        while let Some(frame) = stack.pop() {
            charge(1)?;
            let node = frame.node;
            let macro_context =
                frame.under_macro || matches!(node.kind(), "macro_invocation" | "macro_definition");

            if node.kind() == "use_declaration" && !macro_context {
                collect_imports(
                    node,
                    source,
                    &frame.module_path,
                    &mut imports,
                    &mut shadowed_names,
                );
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
            if !macro_context
                && node.kind() == "mod_item"
                && let Some(name) = node
                    .child_by_field_name("name")
                    .map(|name| rust_node_text(name, source).to_string())
            {
                child_module_path.push(name);
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
            declarations,
            by_path,
            imports,
            shadowed_names,
            states: HashMap::new(),
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
    /// index.  Nodes from another tree are conservatively unresolved.
    pub fn classify_type(&self, type_node: Node<'tree>) -> RustOwnershipClass {
        if has_macro_ancestor(type_node) {
            return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::MacroExpansion);
        }
        if has_unsafe_ancestor(type_node) {
            return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        }
        if type_node.kind() == "reference_type" {
            if reference_referent(type_node)
                .is_some_and(|referent| referent.kind() == "pointer_type")
            {
                return RustOwnershipClass::Incomplete(RustOwnershipIncomplete::RawPointer);
            }
            return if reference_is_mutable(type_node) {
                RustOwnershipClass::MutableReference
            } else {
                RustOwnershipClass::SharedReference
            };
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
                        array_element(left).ok_or(RustOwnershipIncomplete::MissingType)?;
                    let right_element =
                        array_element(right).ok_or(RustOwnershipIncomplete::MissingType)?;
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
                        slice_element(left).ok_or(RustOwnershipIncomplete::MissingType)?;
                    let right_element =
                        slice_element(right).ok_or(RustOwnershipIncomplete::MissingType)?;
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
            let Some(source_element) = array_element(source_referent) else {
                return RustReferenceCoercion::Incomplete(RustOwnershipIncomplete::MissingType);
            };
            let Some(target_element) = array_element(target_referent) else {
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
        let mut values = HashMap::new();
        let mut stack = vec![(type_node, false)];
        while let Some((node, finish)) = stack.pop() {
            let key = node.id();
            if values.contains_key(&key) {
                continue;
            }
            if finish {
                let result = if node.kind() == "array_type" {
                    let Some(element) = array_element(node) else {
                        values.insert(
                            key,
                            EvalState::Incomplete(RustOwnershipIncomplete::MissingType),
                        );
                        continue;
                    };
                    values
                        .get(&element.id())
                        .copied()
                        .expect("array element was visited before its parent")
                } else {
                    aggregate_result(
                        named_children(node)
                            .into_iter()
                            .filter(|child| is_type_node(*child))
                            .map(|child| {
                                values
                                    .get(&child.id())
                                    .copied()
                                    .expect("tuple child was visited before its parent")
                            }),
                    )
                };
                values.insert(key, result);
                continue;
            }
            if has_macro_ancestor(node) {
                values.insert(
                    key,
                    EvalState::Incomplete(RustOwnershipIncomplete::MacroExpansion),
                );
                continue;
            }
            if has_unsafe_ancestor(node) {
                values.insert(
                    key,
                    EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType),
                );
                continue;
            }
            match node.kind() {
                "array_type" => {
                    stack.push((node, true));
                    if let Some(element) = array_element(node) {
                        stack.push((element, false));
                    }
                }
                "tuple_type" => {
                    stack.push((node, true));
                    let children = named_children(node);
                    for child in children.into_iter().rev() {
                        if is_type_node(child) {
                            stack.push((child, false));
                        }
                    }
                }
                "primitive_type" => {
                    let state = if is_copy_primitive(node, self.source) {
                        EvalState::Copy
                    } else {
                        EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType)
                    };
                    values.insert(key, state);
                }
                "unit_type" => {
                    values.insert(key, EvalState::Copy);
                }
                "never_type" => {
                    values.insert(
                        key,
                        EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType),
                    );
                }
                "reference_type" => {
                    let state = match reference_referent(node) {
                        None => EvalState::Incomplete(RustOwnershipIncomplete::MissingType),
                        Some(referent) if referent.kind() == "pointer_type" => {
                            EvalState::Incomplete(RustOwnershipIncomplete::RawPointer)
                        }
                        Some(_) if reference_is_mutable(node) => EvalState::Move,
                        Some(_) => EvalState::Copy,
                    };
                    values.insert(key, state);
                }
                "pointer_type" => {
                    values.insert(
                        key,
                        EvalState::Incomplete(RustOwnershipIncomplete::RawPointer),
                    );
                }
                "type_identifier"
                | "identifier"
                | "scoped_type_identifier"
                | "scoped_identifier" => {
                    values.insert(key, self.classify_nominal_reference(node));
                }
                "generic_type" => {
                    values.insert(
                        key,
                        EvalState::Incomplete(RustOwnershipIncomplete::GenericObligation),
                    );
                }
                _ => {
                    values.insert(
                        key,
                        EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType),
                    );
                }
            }
        }
        values
            .get(&type_node.id())
            .copied()
            .expect("root type node was visited")
    }

    fn classify_nominal_reference(&self, type_node: Node<'tree>) -> EvalState {
        if !valid_path_shape(type_node) {
            return EvalState::Incomplete(RustOwnershipIncomplete::UnsupportedType);
        }
        let Some(path_nodes) = rust_path_segments(type_node) else {
            return EvalState::Incomplete(RustOwnershipIncomplete::UnresolvedPath);
        };
        let path = path_nodes
            .iter()
            .map(|segment| rust_node_text(*segment, self.source).to_string())
            .collect::<Vec<_>>();
        let module_path = lexical_module_path(type_node, self.source);
        let Some(candidates) = self.resolve_nominal_candidates(&module_path, &path) else {
            return EvalState::Incomplete(RustOwnershipIncomplete::UnresolvedPath);
        };
        if candidates.len() != 1 {
            return EvalState::Incomplete(RustOwnershipIncomplete::AmbiguousIdentity);
        }
        match self
            .states
            .get(&candidates[0])
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
        let path_nodes =
            rust_path_segments(type_node).ok_or(RustOwnershipIncomplete::UnresolvedPath)?;
        let path = path_nodes
            .iter()
            .map(|segment| rust_node_text(*segment, self.source).to_string())
            .collect::<Vec<_>>();
        let module_path = lexical_module_path(type_node, self.source);
        let candidates = self
            .resolve_nominal_candidates(&module_path, &path)
            .ok_or(RustOwnershipIncomplete::UnresolvedPath)?;
        if candidates.len() != 1 {
            return Err(RustOwnershipIncomplete::AmbiguousIdentity);
        }
        match self
            .states
            .get(&candidates[0])
            .copied()
            .expect("nominal candidate is indexed")
        {
            NominalState::Pending => Err(RustOwnershipIncomplete::CyclicNominal),
            NominalState::Incomplete(reason) => Err(reason),
            NominalState::Copy | NominalState::Move => Ok(candidates[0]),
        }
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
        let declaration = &mut self.declarations[candidates[0]];
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
                declaration.evidence.wrong_builtin_count += 1;
            }
            return;
        };
        if implementation.negative {
            if trait_kind == BuiltinTrait::Copy {
                declaration.evidence.negative_copy = true;
            }
            return;
        }
        match trait_kind {
            BuiltinTrait::Copy => declaration.evidence.copy_count += 1,
            BuiltinTrait::Clone => declaration.evidence.clone_count += 1,
            BuiltinTrait::Drop => declaration.evidence.drop_count += 1,
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
struct ScanFrame<'tree> {
    node: Node<'tree>,
    module_path: Vec<String>,
    under_macro: bool,
}

fn nominal_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
    module_path: &[String],
    shadowed: &mut HashSet<ShadowedBinding>,
) -> Option<NominalDeclaration<'tree>> {
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
    let evidence = derive_evidence(node, source);
    Some(NominalDeclaration {
        identity,
        payload_types,
        generic: node.child_by_field_name("type_parameters").is_some() || has_where_clause(node),
        malformed_payload,
        evidence,
    })
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
    let mut sibling = node.prev_named_sibling();
    while let Some(attribute_item) = sibling {
        if matches!(attribute_item.kind(), "line_comment" | "block_comment") {
            sibling = attribute_item.prev_named_sibling();
            continue;
        }
        if attribute_item.kind() != "attribute_item" {
            break;
        }
        let Some(attribute) = attribute_item.named_child(0) else {
            break;
        };
        let Some(path) = attribute.named_child(0) else {
            break;
        };
        if path.kind() == "identifier" && rust_node_text(path, source) == "derive" {
            let Some(arguments) = attribute.child_by_field_name("arguments") else {
                evidence.malformed_derive = true;
                sibling = attribute_item.prev_named_sibling();
                continue;
            };
            let Ok(traits) = derive_builtin_traits(arguments, source) else {
                evidence.malformed_derive = true;
                sibling = attribute_item.prev_named_sibling();
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
        sibling = attribute_item.prev_named_sibling();
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

fn collect_imports(
    node: Node<'_>,
    source: &str,
    module_path: &[String],
    imports: &mut Vec<ImportBinding>,
    shadowed: &mut HashSet<ShadowedBinding>,
) {
    for import in rust_imports_with_visibility_from_use_declaration(node, source) {
        match import.binding_name() {
            RustImportBindingName::Glob => {
                for name in ["Copy", "Clone", "Drop"] {
                    shadowed.insert(ShadowedBinding {
                        module_path: module_path.to_vec(),
                        name: name.to_string(),
                    });
                }
                imports.push(ImportBinding {
                    module_path: module_path.to_vec(),
                    local_name: String::new(),
                    target_path: import.path,
                    wildcard: true,
                });
            }
            RustImportBindingName::Named(name) => {
                if name == "_" {
                    continue;
                }
                shadowed.insert(ShadowedBinding {
                    module_path: module_path.to_vec(),
                    name: name.to_string(),
                });
                imports.push(ImportBinding {
                    module_path: module_path.to_vec(),
                    local_name: name.to_string(),
                    target_path: import.path,
                    wildcard: false,
                });
            }
            RustImportBindingName::Unnamed => {}
        }
    }
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

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn has_anonymous_child(node: Node<'_>, kind: &str) -> bool {
    (0..node.child_count()).any(|index| node.child(index).is_some_and(|child| child.kind() == kind))
}

fn has_where_clause(node: Node<'_>) -> bool {
    named_children(node)
        .into_iter()
        .any(|child| child.kind() == "where_clause")
}

fn has_macro_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "macro_invocation" | "macro_definition") {
            return true;
        }
        node = parent;
    }
    false
}

fn has_unsafe_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "unsafe_block" | "unsafe_item") {
            return true;
        }
        if parent.kind() == "function_modifiers" && has_anonymous_child(parent, "unsafe") {
            return true;
        }
        if matches!(parent.kind(), "function_item" | "function_signature_item") {
            let unsafe_modifier = named_children(parent).into_iter().any(|child| {
                child.kind() == "function_modifiers" && has_anonymous_child(child, "unsafe")
            });
            if unsafe_modifier {
                return true;
            }
        }
        node = parent;
    }
    false
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
    node.kind() == "reference_type"
        && named_children(node)
            .into_iter()
            .any(|child| child.kind() == "mutable_specifier")
}

fn array_element(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "array_type").then(|| node.child_by_field_name("element"))?
}

fn slice_element(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "slice_type").then(|| node.child_by_field_name("element"))?
}

fn lexical_module_path(mut node: Node<'_>, source: &str) -> Vec<String> {
    let mut reversed = Vec::new();
    while let Some(parent) = node.parent() {
        if parent.kind() == "mod_item"
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.kind() == "identifier")
        {
            let name = rust_node_text(
                parent
                    .child_by_field_name("name")
                    .expect("checked module name"),
                source,
            )
            .to_string();
            reversed.push(name);
        }
        node = parent;
    }
    reversed.reverse();
    reversed
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
        && named_children(node)
            .into_iter()
            .any(|child| child.kind() == "mutable_specifier")
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
    use tree_sitter::Parser;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("load Rust grammar");
        parser.parse(source, None).expect("parse Rust source")
    }

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
    fn proves_scalars_recursive_aggregates_and_references() {
        let source = "struct Pair(u8, (bool, [i32; 2]));\nfn f(x: &u8, y: &mut u8) {}\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "u8")),
            RustOwnershipClass::ScalarCopy
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "(bool, [i32; 2])")),
            RustOwnershipClass::AggregateCopy
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "&u8")),
            RustOwnershipClass::SharedReference
        );
        assert_eq!(
            index.classify_type(type_named(tree.root_node(), source, "&mut u8")),
            RustOwnershipClass::MutableReference
        );
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
    fn literal_transfer_uses_the_exact_destination_primitive_category() {
        let source = "fn f() -> i32 { 1 } fn g() -> bool { true }\n";
        let tree = parse(source);
        let index =
            RustOwnershipIndex::build(tree.root_node(), source, |_| Ok::<_, ()>(())).unwrap();
        let mut nodes = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            nodes.push(node);
            stack.extend(named_children(node));
        }
        let integer = nodes
            .iter()
            .copied()
            .find(|node| node.kind() == "integer_literal")
            .expect("integer literal");
        let integer_type = type_named(tree.root_node(), source, "i32");
        let boolean_type = type_named(tree.root_node(), source, "bool");
        assert_eq!(
            index.classify_literal_for_type(integer, integer_type),
            RustOwnershipClass::ScalarCopy
        );
        assert_eq!(
            index.classify_literal_for_type(integer, boolean_type),
            RustOwnershipClass::Incomplete(RustOwnershipIncomplete::UnsupportedType)
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
    fn unqualified_builtin_trait_spelling_is_not_exact_identity() {
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
