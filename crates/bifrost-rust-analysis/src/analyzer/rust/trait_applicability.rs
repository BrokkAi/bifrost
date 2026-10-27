//! Query-local Rust implementation evidence for modeled method competition.
//!
//! Absence is a proof, never the absence of a positive row. The artifact
//! inventories close only their source set; workspace impls are checked too.

use crate::analyzer::RustAnalyzer;
use crate::analyzer::semantic_model::{
    GenericTraitBound, ImplementedTraitFact, MemberFact, RustSelfPattern, SemanticModelSymbol,
    TypeRef,
};
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::{
    SemanticModelOverlay, owner_declaration,
};
use brokk_bifrost_analysis::analyzer::store::active_models::ResolvedActiveSemanticModels;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_rust::declarations::rust_node_text;
use brokk_bifrost_rust::graph_support::RustFactSource;
use brokk_bifrost_semantic::analyzer::semantic_model::model::{
    additional_implementation_may_apply, provably_does_not_implement,
};
use std::sync::Arc;

pub(super) struct ModelApplicability<'a> {
    analyzer: &'a dyn IAnalyzer,
    rust: &'a RustAnalyzer,
    overlay: &'a SemanticModelOverlay,
    active: &'a ResolvedActiveSemanticModels,
    sized_parameters: std::collections::HashSet<String>,
}

impl<'a> ModelApplicability<'a> {
    pub(super) fn new(
        analyzer: &'a dyn IAnalyzer,
        rust: &'a RustAnalyzer,
        overlay: &'a SemanticModelOverlay,
        active: &'a ResolvedActiveSemanticModels,
    ) -> Self {
        Self {
            analyzer,
            rust,
            overlay,
            active,
            sized_parameters: Default::default(),
        }
    }

    pub(super) fn owner(&self, ty: &TypeRef) -> Option<Arc<SemanticModelSymbol>> {
        match ty {
            TypeRef::Named { name, .. } => self.overlay.symbols_named(name).unique(),
            TypeRef::Declared { id, .. } => self.overlay.symbols_with_id(id).unique(),
            TypeRef::Slice { .. } => self.overlay.symbols_named("core.primitive.slice").unique(),
            TypeRef::FixedArray { .. } => {
                self.overlay.symbols_named("core.primitive.array").unique()
            }
            _ => None,
        }
    }

    pub(super) fn member(&self, symbol: &SemanticModelSymbol) -> Option<Arc<MemberFact>> {
        self.active
            .all_member_records_with_id(&symbol.id)
            .find(|record| record.shard.manifest.semantic_sha256 == symbol.provenance.pack_digest)
            .map(|record| record.record)
    }

    pub(super) fn provably_absent(
        &self,
        receiver: &SemanticModelSymbol,
        trait_: &SemanticModelSymbol,
    ) -> bool {
        self.absent(receiver, trait_, 16)
    }

    pub(super) fn additional_implementation_may_apply(
        &self,
        receiver: &SemanticModelSymbol,
        trait_: &SemanticModelSymbol,
        actual: &TypeRef,
        artifact_excludes: impl FnOnce() -> bool,
    ) -> Option<bool> {
        additional_implementation_may_apply(
            artifact_excludes,
            || self.workspace_coherence_allows_impl(receiver, trait_, actual),
            || external_workspace_impl_may_apply(self.analyzer, self.rust, trait_, receiver, self),
        )
    }

    fn workspace_coherence_allows_impl(
        &self,
        receiver: &SemanticModelSymbol,
        trait_: &SemanticModelSymbol,
        actual: &TypeRef,
    ) -> bool {
        // #6542: a downstream crate cannot implement a foreign trait with no
        // type arguments for a foreign, non-fundamental type head. Its local
        // generic arguments do not make that head local. No workspace scan or
        // opaque macro can add a legal impl for this pair. Parameterized traits
        // can admit a local trait argument (AsMut<Local> for Vec<u8>); fundamental
        // wrappers (&, &mut, Box, Pin) can expose a local receiver. Preserve the
        // conservative path for those wrappers, even references to foreign
        // types, and for declarations without source-artifact authority.
        if receiver.provenance.extraction.is_none()
            || trait_.provenance.extraction.is_none()
            || matches!(actual, TypeRef::ByRef { .. } | TypeRef::Pointer { .. })
            || [
                "alloc.boxed.Box",
                "std.boxed.Box",
                "core.pin.Pin",
                "std.pin.Pin",
            ]
            .iter()
            .any(|name| {
                receiver.qualified_name == *name
                    || receiver.aliases.iter().any(|alias| alias == name)
            })
        {
            return true;
        }
        !owner_declaration(self.active, trait_).is_some_and(|fact| fact.type_parameters.is_empty())
            || owner_declaration(self.active, receiver).is_none_or(|fact| {
                !matches!(
                    fact.type_kind,
                    crate::analyzer::semantic_model::TypeKind::Struct
                        | crate::analyzer::semantic_model::TypeKind::Enum
                        | crate::analyzer::semantic_model::TypeKind::Union
                )
            })
    }

    // Recursion has an explicit, small depth bound. Cyclic obligations and
    // projections stay unknown rather than turning into negative evidence.
    fn absent(
        &self,
        receiver: &SemanticModelSymbol,
        trait_: &SemanticModelSymbol,
        depth: u8,
    ) -> bool {
        if depth == 0 || receiver.provenance.pack_digest != trait_.provenance.pack_digest {
            return false;
        }
        let (Some(owner), Some(trait_fact)) = (
            owner_declaration(self.active, receiver),
            owner_declaration(self.active, trait_),
        ) else {
            return false;
        };
        provably_does_not_implement(
            &owner,
            &trait_fact,
            |fact| self.implementation(receiver, fact, depth - 1),
            |rule| {
                let matched = self.pattern(receiver, &rule.self_pattern);
                if matched == Some(false) {
                    return matched;
                }
                let bounds = self.bounds(
                    receiver,
                    &rule.bounds,
                    match &rule.self_pattern {
                        RustSelfPattern::Parameter { name } => Some(name.as_str()),
                        _ => None,
                    },
                    depth - 1,
                );
                if bounds == Some(false) || matched == Some(true) {
                    bounds
                } else {
                    None
                }
            },
        )
    }

    fn pattern(&self, receiver: &SemanticModelSymbol, pattern: &RustSelfPattern) -> Option<bool> {
        match pattern {
            RustSelfPattern::Parameter { .. } => Some(true),
            RustSelfPattern::Reference { .. } => Some(false),
            RustSelfPattern::Constructor { owner, arguments } => {
                let primitive = match owner {
                    TypeRef::Slice { .. } => Some("slice"),
                    TypeRef::FixedArray { .. } => Some("array"),
                    TypeRef::Tuple { .. } => Some("tuple"),
                    TypeRef::Pointer { .. } => Some("pointer"),
                    _ => None,
                };
                if let Some(primitive) = primitive {
                    let name = format!("core.primitive.{primitive}");
                    // The head can contradict a nominal receiver, but a
                    // matching builtin shape still needs element/length proof.
                    return if receiver.qualified_name == name || receiver.aliases.contains(&name) {
                        None
                    } else {
                        Some(false)
                    };
                }
                // The constructor head remains an identity even when a
                // private artifact type has no externally published TypeFact.
                // Its absence from the overlay must not erase a contradiction.
                let same = match self.owner(owner) {
                    Some(expected) if expected.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::TypeAlias => return None,
                    Some(expected) => expected.id == receiver.id,
                    None => match owner {
                        TypeRef::Named { name, .. } => name == &receiver.qualified_name || receiver.aliases.contains(name),
                        TypeRef::Declared { id, .. } => id == &receiver.id,
                        _ => return None,
                    },
                };
                if !same {
                    return Some(false);
                }
                // Receiver owner evidence alone cannot disprove or establish
                // a specialization on its generic arguments.
                arguments
                    .iter()
                    .all(|arg| matches!(arg, RustSelfPattern::Parameter { .. }))
                    .then_some(true)
            }
        }
    }

    fn implementation(
        &self,
        receiver: &SemanticModelSymbol,
        fact: &ImplementedTraitFact,
        depth: u8,
    ) -> Option<bool> {
        let matched = fact
            .self_pattern
            .as_ref()
            .map_or(Some(true), |pattern| self.pattern(receiver, pattern));
        if matched == Some(false) {
            return matched;
        }
        let bounds = self.bounds(receiver, &fact.bounds, None, depth);
        if bounds == Some(false) || matched == Some(true) {
            bounds
        } else {
            None
        }
    }

    fn bounds(
        &self,
        receiver: &SemanticModelSymbol,
        bounds: &[GenericTraitBound],
        self_parameter: Option<&str>,
        depth: u8,
    ) -> Option<bool> {
        let mut unknown = false;
        for bound in bounds.iter().filter(|bound| !bound.maybe) {
            // A bare-parameter blanket rule's parameter denotes the receiver;
            // other subjects need substitution evidence, so remain unknown.
            let on_self = matches!(&bound.subject, TypeRef::TypeParameter { name } if name == "Self" || Some(name.as_str()) == self_parameter)
                || matches!(&bound.subject, TypeRef::Named { name, .. } if name == "Self" || Some(name.as_str()) == self_parameter);
            if !on_self {
                unknown = true;
                continue;
            }
            let Some(trait_) = self.owner(&bound.bound.trait_type) else {
                unknown = true;
                continue;
            };
            // A downstream impl with a local trait argument can invalidate
            // source-set absence. Without its substitution, retain unknown.
            if owner_declaration(self.active, &trait_)
                .is_some_and(|fact| fact.type_parameters.is_empty())
                && self.additional_implementation_may_apply(
                    receiver,
                    &trait_,
                    &self.abstract_receiver(receiver),
                    || self.absent(receiver, &trait_, depth),
                ) == Some(false)
            {
                return Some(false);
            }
            unknown = true;
        }
        if unknown { None } else { Some(true) }
    }

    pub(super) fn receiver_type(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        ty: tree_sitter::Node<'_>,
    ) -> Option<TypeRef> {
        let mut ancestor = Some(ty);
        let mut seen = std::collections::HashSet::new();
        while let Some(node) = ancestor {
            if let Some(parameters) = node.child_by_field_name("type_parameters") {
                let mut cursor = parameters.walk();
                for parameter in parameters.named_children(&mut cursor) {
                    let Some(name) = parameter.child_by_field_name("name") else {
                        continue;
                    };
                    let name = rust_node_text(name, source);
                    if !seen.insert(name.to_owned()) {
                        continue;
                    }
                    let maybe_sized =
                        parameter
                            .child_by_field_name("bounds")
                            .is_some_and(|bounds| {
                                let mut cursor = bounds.walk();
                                bounds
                                    .named_children(&mut cursor)
                                    .any(|bound| bound.kind() == "removed_trait_bound")
                            });
                    if !maybe_sized {
                        self.sized_parameters.insert(name.to_owned());
                    }
                }
            }
            ancestor = node.parent();
        }
        self.source_type(analyzer, file, source, ty, 16)
    }

    fn source_type(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
        ty: tree_sitter::Node<'_>,
        depth: u8,
    ) -> Option<TypeRef> {
        if depth == 0 {
            return None;
        }
        if ty.kind() == "reference_type" {
            return Some(TypeRef::ByRef {
                element: Box::new(self.source_type(
                    analyzer,
                    file,
                    source,
                    ty.child_by_field_name("type")?,
                    depth - 1,
                )?),
                reference_kind: crate::analyzer::semantic_model::TypeRefReferenceKind::Lvalue,
            });
        }
        if ty.kind() == "primitive_type" {
            return Some(TypeRef::Named {
                name: format!("core.primitive.{}", rust_node_text(ty, source)),
                arguments: vec![],
                nullable: false,
            });
        }
        if ty.kind() == "type_identifier"
            && self.sized_parameters.contains(rust_node_text(ty, source))
        {
            return Some(TypeRef::TypeParameter {
                name: rust_node_text(ty, source).into(),
            });
        }
        let (owner, arguments) =
            super::std_types::rust_nominal_receiver_application_with_operation(
                analyzer, file, source, ty, None, None, None,
            )?;
        let symbol = self.overlay.symbols_named(&owner).unique()?;
        let fact = owner_declaration(self.active, &symbol)?;
        let mut actual = arguments
            .into_iter()
            .map(|argument| {
                self.source_type(analyzer, file, source, argument, depth - 1)
                    .unwrap_or(TypeRef::Unknown)
            })
            .collect::<Vec<_>>();
        complete_type_arguments(&fact, &mut actual)?;
        Some(TypeRef::Declared {
            id: symbol.id.clone(),
            arguments: actual,
            nullable: false,
        })
    }

    pub(super) fn abstract_receiver(&self, receiver: &SemanticModelSymbol) -> TypeRef {
        let arguments = owner_declaration(self.active, receiver)
            .map(|fact| vec![TypeRef::Unknown; fact.type_parameters.len()])
            .unwrap_or_default();
        TypeRef::Declared {
            id: receiver.id.clone(),
            arguments,
            nullable: false,
        }
    }

    pub(super) fn deref_target(
        &self,
        receiver: &SemanticModelSymbol,
        actual: &TypeRef,
    ) -> Option<TypeRef> {
        let declaration = owner_declaration(self.active, receiver)?;
        let deref = self
            .overlay
            .symbols_named("core.ops.Deref")
            .unique()
            .or_else(|| self.overlay.symbols_named("std.ops.Deref").unique())?;
        let mut target = None;
        let mut proven = false;
        for fact in &declaration.implemented_traits {
            if fact.is_negative
                || !self
                    .owner(&fact.trait_type)
                    .is_some_and(|owner| owner.id == deref.id)
            {
                continue;
            }
            let mut bindings = std::collections::HashMap::new();
            if let Some(pattern) = &fact.self_pattern {
                self.bind_pattern(actual, pattern, &mut bindings)?;
            }
            bindings.insert("Self".into(), actual.clone());
            proven |= self.positive_bounds(&fact.bounds, &bindings, 16);
            let binding = fact
                .associated_types
                .iter()
                .find(|binding| binding.name == "Target")?;
            let found = substitute(&binding.r#type, &bindings, 16)?;
            if target.as_ref().is_some_and(|old| old != &found) {
                return None;
            }
            target = Some(found);
        }
        proven.then_some(target).flatten()
    }

    fn bind_pattern(
        &self,
        actual: &TypeRef,
        pattern: &RustSelfPattern,
        bindings: &mut std::collections::HashMap<String, TypeRef>,
    ) -> Option<()> {
        let mut pending = vec![(actual, pattern)];
        while let Some((actual, pattern)) = pending.pop() {
            match pattern {
                RustSelfPattern::Parameter { name } => {
                    if let Some(old) = bindings.get(name) {
                        if actual.contains_unknown() || old != actual {
                            return None;
                        }
                    } else {
                        bindings.insert(name.clone(), actual.clone());
                    }
                }
                RustSelfPattern::Constructor { owner, arguments } => {
                    if self.owner(actual)?.id != self.owner(owner)?.id {
                        return None;
                    }
                    let actual_arguments = match actual {
                        TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                            arguments.as_slice()
                        }
                        TypeRef::Slice { element } => std::slice::from_ref(element.as_ref()),
                        _ => return None,
                    };
                    if actual_arguments.len() != arguments.len() {
                        return None;
                    }
                    pending.extend(actual_arguments.iter().zip(arguments));
                }
                RustSelfPattern::Reference { .. } => return None,
            }
        }
        Some(())
    }

    fn positive_bounds(
        &self,
        bounds: &[GenericTraitBound],
        bindings: &std::collections::HashMap<String, TypeRef>,
        depth: u8,
    ) -> bool {
        bounds.iter().filter(|bound| !bound.maybe).all(|bound| {
            let Some(subject) = substitute(&bound.subject, bindings, depth) else {
                return false;
            };
            let Some(trait_) = self.owner(&bound.bound.trait_type) else {
                return false;
            };
            self.positive(&subject, &trait_, depth)
        })
    }

    fn positive(&self, actual: &TypeRef, trait_: &SemanticModelSymbol, depth: u8) -> bool {
        if depth == 0 {
            return false;
        }
        if self
            .overlay
            .symbols_named("core.marker.Sized")
            .unique()
            .is_some_and(|sized| sized.id == trait_.id)
        {
            match actual {
                TypeRef::ByRef { .. } => return true,
                TypeRef::TypeParameter { name } if self.sized_parameters.contains(name) => {
                    return true;
                }
                TypeRef::Named { name, .. }
                    if name.starts_with("core.primitive.")
                        && !matches!(
                            name.as_str(),
                            "core.primitive.str" | "core.primitive.slice"
                        ) =>
                {
                    return true;
                }
                _ => {}
            }
        }
        let Some(receiver) = self.owner(actual) else {
            return false;
        };
        let Some(declaration) = owner_declaration(self.active, &receiver) else {
            return false;
        };
        for fact in declaration
            .implemented_traits
            .iter()
            .filter(|fact| !fact.is_negative)
        {
            let Some(implemented) = self.owner(&fact.trait_type) else {
                continue;
            };
            let reaches = implemented.id == trait_.id
                || self
                    .overlay
                    .ancestors_of(&implemented)
                    .records
                    .iter()
                    .any(|ancestor| ancestor.id == trait_.id);
            if !reaches {
                continue;
            }
            let mut bindings = std::collections::HashMap::new();
            if let Some(pattern) = &fact.self_pattern
                && self.bind_pattern(actual, pattern, &mut bindings).is_none()
            {
                continue;
            }
            bindings.insert("Self".into(), actual.clone());
            if self.positive_bounds(&fact.bounds, &bindings, depth - 1) {
                return true;
            }
        }
        false
    }
}

pub(super) fn workspace_trait_may_apply(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    trait_: &CodeUnit,
    receiver: &SemanticModelSymbol,
    model: &ModelApplicability<'_>,
) -> Option<bool> {
    let live = rust.live_blobs();
    let mut files = workspace_read(brokk_bifrost_rust::graph_support::impl_files_of_trait(
        rust, trait_,
    ))?;
    for spelling in workspace_trait_spellings(analyzer, rust, trait_.identifier())? {
        if macro_may_name_trait(rust, &spelling)? {
            return Some(true);
        }
        for row in workspace_read(rust.rust_unresolved_trait_impl_files(&spelling))? {
            files.extend(live.paths_for_oid(row.impl_blob));
        }
    }
    files.sort();
    files.dedup();
    workspace_impls_may_apply(
        analyzer,
        rust,
        &files,
        &TraitIdentity::Workspace(trait_.clone()),
        receiver,
        model,
    )
}

pub(super) fn external_workspace_impl_may_apply(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    trait_: &SemanticModelSymbol,
    receiver: &SemanticModelSymbol,
    model: &ModelApplicability<'_>,
) -> Option<bool> {
    let live = rust.live_blobs();
    let mut files = std::collections::HashSet::new();
    for spelling in workspace_trait_spellings(analyzer, rust, &trait_.name)? {
        for row in workspace_read(rust.rust_unresolved_trait_impl_files(&spelling))? {
            files.extend(live.paths_for_oid(row.impl_blob));
        }
        // A macro may contribute an impl not present in the ordinary rows.
        // Trait arguments and fundamental receivers such as Box<Local> can
        // satisfy the orphan rule. Without that structured expansion, keep
        // applicability open even for a nongeneric foreign trait.
        if macro_may_name_trait(rust, &spelling)? {
            return Some(true);
        }
    }
    let files = files.into_iter().collect::<Vec<_>>();
    workspace_impls_may_apply(
        analyzer,
        rust,
        &files,
        &TraitIdentity::Model(trait_.id.clone()),
        receiver,
        model,
    )
}

// Both source and modeled traits can be renamed before an impl header or an
// opaque macro mentions them. This worklist belongs to the current query.
fn workspace_trait_spellings(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    name: &str,
) -> Option<std::collections::HashSet<String>> {
    let live = rust.live_blobs();
    let mut spellings = std::collections::HashSet::new();
    let mut pending = vec![name.to_owned()];
    let scope = AnalyzerQueryScope::new(analyzer);
    while let Some(spelling) = pending.pop() {
        if !spellings.insert(spelling.clone()) {
            continue;
        }
        for blob in workspace_read(rust.rust_module_import_candidate_blobs(&spelling))? {
            for file in live.paths_for_oid(blob) {
                let provider = analyzer.import_analysis_provider_for_file(&file)?;
                for import in provider.import_info_of(scope.token(), &file).iter() {
                    if import.path.as_ref().and_then(|path| path.segments.last()) == Some(&spelling)
                        && let Some(alias) = &import.alias
                    {
                        pending.push(alias.clone());
                    }
                }
            }
        }
    }
    Some(spellings)
}

fn workspace_impls_may_apply(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    files: &[ProjectFile],
    trait_identity: &TraitIdentity,
    receiver: &SemanticModelSymbol,
    model: &ModelApplicability<'_>,
) -> Option<bool> {
    let scope = AnalyzerQueryScope::new(analyzer);
    for file in files {
        let prepared = rust.prepared_syntax(scope.token(), file)?;
        let source = prepared.source();
        let mut pending = vec![prepared.tree().root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() != "impl_item" {
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
                continue;
            }
            let Some(trait_node) = node.child_by_field_name("trait") else {
                continue;
            };
            let trait_head = if trait_node.kind() == "generic_type" {
                trait_node.child_by_field_name("type")?
            } else {
                trait_node
            };
            match resolve_trait(analyzer, file, source, prepared.tree(), trait_head, model) {
                Some(identity) if &identity != trait_identity => continue,
                None => return Some(true),
                _ => {}
            }
            let target = node.child_by_field_name("type")?;
            let generic_self =
                node.child_by_field_name("type_parameters")
                    .is_some_and(|parameters| {
                        let mut cursor = parameters.walk();
                        parameters.named_children(&mut cursor).any(|parameter| {
                            parameter.child_by_field_name("name").is_some_and(|name| {
                                target.kind() == "type_identifier"
                                    && rust_node_text(name, source)
                                        == rust_node_text(target, source)
                            })
                        })
                    });
            // A downstream blanket impl of a foreign trait for a bare type
            // parameter cannot satisfy coherence. In incomplete/invalid source,
            // keep it unknown without recursively solving workspace bounds.
            // Workspace-owned traits can have such blanket impls; their bound
            // checks below consult external rows, whose bare-parameter cases
            // stop here, so this call chain has a fixed depth of at most two.
            if generic_self && matches!(trait_identity, TraitIdentity::Model(_)) {
                return Some(true);
            }
            if generic_self {
                let self_name = rust_node_text(target, source);
                let mut bound_nodes = Vec::new();
                if let Some(parameters) = node.child_by_field_name("type_parameters") {
                    let mut cursor = parameters.walk();
                    for parameter in parameters.named_children(&mut cursor) {
                        if parameter
                            .child_by_field_name("name")
                            .is_some_and(|name| rust_node_text(name, source) == self_name)
                            && let Some(bounds) = parameter.child_by_field_name("bounds")
                        {
                            bound_nodes.push(bounds);
                        }
                    }
                }
                let mut cursor = node.walk();
                for clause in node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "where_clause")
                {
                    let mut cursor = clause.walk();
                    for predicate in clause.named_children(&mut cursor) {
                        if predicate
                            .child_by_field_name("left")
                            .is_some_and(|left| rust_node_text(left, source) == self_name)
                            && let Some(bounds) = predicate.child_by_field_name("bounds")
                        {
                            bound_nodes.push(bounds);
                        }
                    }
                }
                let mut impossible = false;
                for bounds in bound_nodes {
                    let mut cursor = bounds.walk();
                    for bound in bounds.named_children(&mut cursor) {
                        if bound.kind() == "lifetime" || bound.kind() == "removed_trait_bound" {
                            continue;
                        }
                        if let Some(TraitIdentity::Model(id)) =
                            resolve_trait(analyzer, file, source, prepared.tree(), bound, model)
                            && let Some(trait_) = model.overlay.symbols_with_id(&id).unique()
                        {
                            impossible |= owner_declaration(model.active, &trait_)
                                .is_some_and(|fact| fact.type_parameters.is_empty())
                                && !model.additional_implementation_may_apply(
                                    receiver,
                                    &trait_,
                                    &model.abstract_receiver(receiver),
                                    || model.provably_absent(receiver, &trait_),
                                )?;
                        }
                    }
                }
                if !impossible {
                    return Some(true);
                }
            } else {
                let nominal = super::std_types::rust_nominal_receiver_owner_with_operation(
                    analyzer, file, source, target, None, None, None,
                );
                match nominal {
                    Some(owner) if owner != receiver.qualified_name => continue,
                    None => match resolve_trait(
                        analyzer,
                        file,
                        source,
                        prepared.tree(),
                        target,
                        model,
                    ) {
                        Some(TraitIdentity::Workspace(unit))
                            if !workspace_read(
                                brokk_bifrost_rust::graph_support::is_rust_type_alias_declaration(
                                    rust, &unit,
                                ),
                            )? =>
                        {
                            continue;
                        }
                        _ => return Some(true),
                    },
                    _ => return Some(true),
                }
            }
        }
    }
    Some(false)
}

#[derive(PartialEq, Eq)]
enum TraitIdentity {
    Workspace(CodeUnit),
    Model(String),
}

fn resolve_trait(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    node: tree_sitter::Node<'_>,
    model: &ModelApplicability<'_>,
) -> Option<TraitIdentity> {
    let value = resolve_source_definition(analyzer, file, source, tree, node)?;
    match value.definitions.as_slice() {
        [unit] => return Some(TraitIdentity::Workspace(unit.clone())),
        [] => {}
        _ => return None,
    }
    match value.modeled_definitions.as_slice() {
        [symbol] => return Some(TraitIdentity::Model(symbol.id.clone())),
        [] => {}
        _ => return None,
    }
    if let Some((crate_name, name)) = super::std_types::prelude_item_identity_of(&value, "type") {
        let module = brokk_bifrost_rust::prelude::rust_prelude_trait_module(&name)?;
        let symbol = model
            .overlay
            .symbols_named(&format!("{crate_name}.{module}.{name}"))
            .unique()?;
        return Some(TraitIdentity::Model(symbol.id.clone()));
    }
    let subjects = value.diagnostics.iter().filter_map(|diagnostic| diagnostic.claim.as_ref())
        .filter(|claim| claim.kind == brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaimKind::ExternalBoundary)
        .flat_map(|claim| claim.subjects.iter()).collect::<Vec<_>>();
    let [subject] = subjects.as_slice() else {
        return None;
    };
    model
        .overlay
        .symbols_named(subject)
        .unique()
        .map(|symbol| TraitIdentity::Model(symbol.id.clone()))
}

fn resolve_source_definition(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    node: tree_sitter::Node<'_>,
) -> Option<brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome> {
    use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
    use brokk_bifrost_core::analyzer::model::Range;
    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
    let head = if node.kind() == "generic_type" {
        node.child_by_field_name("type")?
    } else {
        node
    };
    let terminal = head.child_by_field_name("name").unwrap_or(head);
    let site = ResolvedReferenceSite {
        path: rust_node_text(head, source).into(),
        text: rust_node_text(terminal, source).into(),
        range: Range {
            start_byte: head.start_byte(),
            end_byte: head.end_byte(),
            start_line: head.start_position().row + 1,
            end_line: head.end_position().row + 1,
        },
        focus_start_byte: terminal.start_byte(),
        focus_end_byte: terminal.end_byte(),
    };
    let resolved =
        brokk_bifrost_analysis::analyzer::usages::get_definition::trace::without_recording(|| {
            super::native_points::resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree: Some(tree),
        site: &site,
        budget:
            brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation: None,
    })
        });
    super::std_types::observe_proof_resolution(&resolved);
    let BoundedResolution::Complete { value, .. } = resolved else {
        return None;
    };
    Some(value)
}

/// Bound surfaces of a resolver-selected lexical type parameter or one of its
/// associated projections. None means this is not a proven lexical receiver;
/// an unresolved bound prevents using any partial list as an exhaustive one.
pub(super) fn lexical_receiver_traits<'a>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    mut ty: tree_sitter::Node<'_>,
    model: &ModelApplicability<'a>,
) -> Option<Vec<Arc<SemanticModelSymbol>>> {
    while ty.kind() == "reference_type" {
        ty = ty.child_by_field_name("type")?;
    }
    let segments = brokk_bifrost_rust::graph_support::rust_path_segments(ty)?;
    let root = *segments.first()?;
    let outcome = resolve_source_definition(analyzer, file, source, tree, root)?;
    let lexical = outcome.lexical_definition.as_ref()?;
    debug_assert!(
        lexical
            .source_file
            .as_ref()
            .is_none_or(|source_file| source_file == file)
    );
    let range = &lexical.declaration_range;
    let mut declaration = tree
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while declaration.kind() != "type_parameter" {
        declaration = declaration.parent()?;
        if matches!(
            declaration.kind(),
            "function_item" | "impl_item" | "trait_item"
        ) {
            return None;
        }
    }
    let owner = declaration.parent()?.parent()?;
    let bounds = brokk_bifrost_rust::structural::rust_declared_type_bounds(
        owner,
        declaration.child_by_field_name("name")?,
        source,
    );
    let mut roots = modeled_bound_traits(analyzer, file, source, tree, bounds, model)?;
    // Associated type declarations retain their own bound hierarchy in packs.
    // Follow that hierarchy rather than parsing any projection spelling.
    for segment in segments.iter().skip(1) {
        let mut projected = Vec::new();
        for owner in lexical_bound_surfaces(&roots, model)? {
            if let Some(associated) = model
                .overlay
                .symbols_named(&format!(
                    "{}.{}",
                    owner.qualified_name,
                    rust_node_text(*segment, source)
                ))
                .unique()
                && !projected
                    .iter()
                    .any(|old: &Arc<SemanticModelSymbol>| old.id == associated.id)
            {
                projected.push(associated);
            }
        }
        // A written projection must name one associated declaration, even
        // when distinct ambiguous declarations would share a method bound.
        if projected.len() != 1 {
            return None;
        }
        roots = projected;
    }
    // Where bounds on projections add to, rather than replace, declared bounds.
    if segments.len() > 1 {
        let bounds = brokk_bifrost_rust::structural::rust_declared_type_bounds(owner, ty, source);
        roots.extend(modeled_bound_traits(
            analyzer, file, source, tree, bounds, model,
        )?);
    }
    Some(
        lexical_bound_surfaces(&roots, model)?
            .into_iter()
            .filter(|symbol| {
                symbol.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::Trait
            })
            .collect(),
    )
}

fn modeled_bound_traits<'a>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    mut bounds: Vec<tree_sitter::Node<'_>>,
    model: &ModelApplicability<'a>,
) -> Option<Vec<Arc<SemanticModelSymbol>>> {
    let mut roots = Vec::new();
    while let Some(bound) = bounds.pop() {
        match bound.kind() {
            "trait_bounds" | "bounded_type" => {
                let mut cursor = bound.walk();
                bounds.extend(bound.named_children(&mut cursor));
            }
            "lifetime" | "removed_trait_bound" => {}
            _ => match resolve_trait(analyzer, file, source, tree, bound, model)? {
                TraitIdentity::Model(id) => {
                    roots.push(model.overlay.symbols_with_id(&id).unique()?)
                }
                // An unresolved workspace bound may declare or inherit the
                // requested name. Do not certify a partial external surface.
                TraitIdentity::Workspace(_) => return None,
            },
        }
    }
    Some(roots)
}

fn lexical_bound_surfaces<'a>(
    roots: &[Arc<SemanticModelSymbol>],
    model: &ModelApplicability<'a>,
) -> Option<Vec<Arc<SemanticModelSymbol>>> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        let ancestors = model.overlay.ancestors_of(root);
        if !ancestors.defects.is_empty()
            || ancestors.disposition
                == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict
        {
            super::std_types::incomplete_proof("lexical_bound_hierarchy_unknown");
            return None;
        }
        for symbol in std::iter::once(Arc::clone(root)).chain(ancestors.records) {
            if seen.insert(symbol.id.clone()) {
                result.push(symbol);
            }
        }
    }
    Some(result)
}

// The substitution depth is bounded by the producer's type nesting contract;
// a deeper or unsupported projection remains unknown for this query.
/// Apply omitted trailing defaults to source applications and modeled Self
/// results alike. Defaults may refer to an earlier owner parameter.
pub(super) fn complete_type_arguments(
    declaration: &crate::analyzer::semantic_model::TypeFact,
    arguments: &mut Vec<TypeRef>,
) -> Option<()> {
    if arguments.len() > declaration.type_parameters.len() {
        return None;
    }
    let mut bindings = declaration
        .type_parameters
        .iter()
        .cloned()
        .zip(arguments.iter().cloned())
        .collect::<std::collections::HashMap<_, _>>();
    for index in arguments.len()..declaration.type_parameters.len() {
        let argument = match declaration
            .type_parameter_defaults
            .get(index)
            .and_then(Option::as_ref)
        {
            Some(crate::analyzer::semantic_model::GenericParameterDefault::Type { r#type }) => {
                substitute(r#type, &bindings, 16).unwrap_or(TypeRef::Unknown)
            }
            _ => TypeRef::Unknown,
        };
        bindings.insert(declaration.type_parameters[index].clone(), argument.clone());
        arguments.push(argument);
    }
    Some(())
}

pub(super) fn substitute(
    ty: &TypeRef,
    bindings: &std::collections::HashMap<String, TypeRef>,
    depth: u8,
) -> Option<TypeRef> {
    if depth == 0 {
        return None;
    }
    Some(match ty {
        TypeRef::TypeParameter { name } => bindings.get(name)?.clone(),
        TypeRef::Named {
            name,
            arguments,
            nullable,
        } => TypeRef::Named {
            name: name.clone(),
            arguments: arguments
                .iter()
                .map(|argument| substitute(argument, bindings, depth - 1))
                .collect::<Option<_>>()?,
            nullable: *nullable,
        },
        TypeRef::Declared {
            id,
            arguments,
            nullable,
        } => TypeRef::Declared {
            id: id.clone(),
            arguments: arguments
                .iter()
                .map(|argument| substitute(argument, bindings, depth - 1))
                .collect::<Option<_>>()?,
            nullable: *nullable,
        },
        TypeRef::Slice { element } => TypeRef::Slice {
            element: Box::new(substitute(element, bindings, depth - 1)?),
        },
        TypeRef::ByRef {
            element,
            reference_kind,
        } => TypeRef::ByRef {
            element: Box::new(substitute(element, bindings, depth - 1)?),
            reference_kind: *reference_kind,
        },
        TypeRef::Unknown => TypeRef::Unknown,
        _ => return None,
    })
}

fn workspace_read<T>(
    result: Result<T, brokk_bifrost_rust::graph_support::RustCargoRouteError>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("reading Rust workspace implementation evidence: {error:?}");
            super::std_types::incomplete_proof("workspace_impl_inventory_unavailable");
            None
        }
    }
}

fn macro_may_name_trait(rust: &RustAnalyzer, name: &str) -> Option<bool> {
    Some(
        workspace_read(rust.rust_identifier_occurrence_blobs(name))?
            .iter()
            .any(|(_, context)| {
                context & brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_MACRO != 0
            }),
    )
}
