//! Conservative Ruby class-set adapter.
//!
//! Ruby classes and member surfaces remain open at run time. This adapter
//! therefore retains useful class and positive-member evidence together with
//! an explicit open bound, and never proves member absence.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSyntaxSource, PreparedSyntaxTree};
use brokk_bifrost_ruby::graph::RubyGraphSource;
use brokk_bifrost_ruby::graph::resolver::{ReceiverMode, ReceiverType, RubySemanticIndex};
use tree_sitter::Node;

use super::RubyAnalyzer;
use crate::analyzer::semantic::type_flow::{
    ClassHierarchy, ClassIdentity, ClassSeed, ExternalClassCache, ExternalMemberDeclaration,
    MemberAccessKind, MemberAccessQuery, MemberDeclaration, MemberLookup, MemberLookupHit,
    TypeFlowAdapter, UnknownReason, analyzer_range_for_span, class_seed_from_lookup_types,
    external_class_identity, file_for_locator, validate_prepared_syntax_for_procedure,
};
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, AllocationSite, CandidateCoverage, MemoryLocationKind,
    ProcedureHandle, SemanticCallSite, SemanticValue, SemanticValueKind, SourceMappingKind,
};
use crate::analyzer::semantic_model::{
    SemanticModelOverlay, SemanticModelSymbolKind, semantic_model_callable_family_id,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupStatus, resolve_ruby_bounded,
};
use crate::analyzer::usages::get_type::{
    TypeLookupStatus, resolve_type_at_reference_site_with_budget,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, CodeUnit, CodeUnitIndex, Language, ProjectFile,
    QueryScope, TypeHierarchyProvider, WorkspaceAnalyzer, resolve_analyzer,
};
use crate::path_utils::rel_path_string;

pub struct RubyTypeFlowAdapter;

fn ruby_analyzer(workspace: &WorkspaceAnalyzer) -> &RubyAnalyzer {
    resolve_analyzer::<RubyAnalyzer>(workspace.analyzer())
        .expect("RubyTypeFlowAdapter serves only workspaces that analyze Ruby")
}

fn overlay_of(workspace: &WorkspaceAnalyzer) -> Option<Arc<SemanticModelOverlay>> {
    workspace
        .analyzer()
        .active_semantic_model_snapshot()
        .and_then(|snapshot| snapshot.semantic_model_overlay().cloned())
}

fn prepared_for(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    let ruby = ruby_analyzer(workspace);
    let scope = AnalyzerQueryScope::new(ruby);
    ruby.inner.prepared_syntax(scope.token(), file)
}

fn current_prepared(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    let prepared = prepared_for(workspace, file)?;
    (matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_))
        && ruby_analyzer(workspace).indexed_source_matches(file, prepared.source()))
    .then_some(prepared)
}

fn prepared_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let prepared = prepared_for(workspace, file).ok_or(UnknownReason::UncertainFlow)?;
    validate_prepared_syntax_for_procedure(workspace, procedure, file, prepared)
}

fn node_at_mapping<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    procedure: &ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> Option<Node<'tree>> {
    let mapping = procedure.semantics().source_mapping(source)?;
    if mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let span = mapping.locator.anchor().span();
    prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
}

fn reference_site(file: &ProjectFile, node: Node<'_>, source: &str) -> ResolvedReferenceSite {
    let range = crate::analyzer::Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    ResolvedReferenceSite {
        path: rel_path_string(file),
        text: node
            .utf8_text(source.as_bytes())
            .expect("a prepared tree spans its own UTF-8 source")
            .to_owned(),
        focus_start_byte: node.start_byte(),
        focus_end_byte: node.end_byte(),
        range,
    }
}

fn open_external_seed(workspace: &WorkspaceAnalyzer, name: &str) -> ClassSeed {
    let mut cache = ExternalClassCache::default();
    external_class_identity(
        overlay_of(workspace).as_deref(),
        Language::Ruby,
        name,
        None,
        &mut cache,
    )
    .map(ClassSeed::ClassWithOpenBound)
    .unwrap_or(ClassSeed::Unknown(UnknownReason::ExternalNotModeled))
}

fn positive(declaration: MemberDeclaration) -> MemberLookup {
    MemberLookup::Present(MemberLookupHit::new(declaration, CandidateCoverage::Open))
}

fn workspace_member_lookup(
    workspace: &WorkspaceAnalyzer,
    class: &CodeUnit,
    member: &str,
) -> MemberLookup {
    if current_prepared(workspace, class.source()).is_none() {
        return MemberLookup::Unknown(UnknownReason::UncertainFlow);
    }
    let ruby = ruby_analyzer(workspace);
    let lookup = AnalyzerDefinitionLookup::new(workspace.analyzer(), Language::Ruby);
    let definitions = |consume: &mut dyn FnMut(&dyn crate::analyzer::BoundedDefinitionLookup)| {
        consume(&lookup);
    };
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let semantic = RubySemanticIndex::build_for_lookup(
        RubyGraphSource {
            token: scope.token(),
            index: workspace.analyzer(),
            definitions: &definitions,
        },
        ruby,
    );
    let visible = semantic.visible_files_from(class.source());
    if visible
        .iter()
        .any(|file| current_prepared(workspace, file).is_none())
    {
        return MemberLookup::Unknown(UnknownReason::UncertainFlow);
    }
    let receiver = ReceiverType {
        owner_fq_name: class.fq_name(),
        mode: ReceiverMode::Instance,
    };
    let mut candidates = semantic.resolve_method_candidates(&lookup, &visible, &receiver, member);
    candidates.sort_by(|left, right| {
        left.fq_name().cmp(&right.fq_name()).then_with(|| {
            left.declaration_id()
                .as_str()
                .cmp(right.declaration_id().as_str())
        })
    });
    candidates.dedup();
    let mut candidates = candidates.into_iter();
    let Some(declaration) = candidates.next() else {
        return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
    };
    if candidates.next().is_some() {
        return MemberLookup::Unknown(UnknownReason::AmbiguousCallee);
    }
    if current_prepared(workspace, declaration.source()).is_none()
        || visible
            .iter()
            .any(|file| current_prepared(workspace, file).is_none())
    {
        return MemberLookup::Unknown(UnknownReason::UncertainFlow);
    }
    positive(MemberDeclaration::Workspace(declaration))
}

fn external_member_lookup(
    overlay: &SemanticModelOverlay,
    kind: MemberAccessKind,
    symbol_id: &str,
    member: &str,
) -> MemberLookup {
    let records = overlay
        .member_target_on_owner(symbol_id, member)
        .records
        .into_iter()
        .filter(|record| {
            record.language == Language::Ruby.config_label()
                && !record.is_static()
                && match kind {
                    MemberAccessKind::Call => matches!(
                        record.kind,
                        SemanticModelSymbolKind::Method | SemanticModelSymbolKind::Constructor
                    ),
                    MemberAccessKind::Load => matches!(
                        record.kind,
                        SemanticModelSymbolKind::Field | SemanticModelSymbolKind::Property
                    ),
                }
        })
        .collect::<Vec<_>>();
    if records.is_empty()
        || records.iter().any(|record| record.provenance.ambiguous)
        || (records.len() > 1
            && (kind != MemberAccessKind::Call
                || semantic_model_callable_family_id(&records).is_none()))
    {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    positive(MemberDeclaration::External(ExternalMemberDeclaration::new(
        records
            .into_iter()
            .map(|record| Box::from(record.id.as_str())),
    )))
}

impl TypeFlowAdapter for RubyTypeFlowAdapter {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn semantics_version(&self) -> AdapterSemanticsVersion {
        AdapterSemanticsVersion::hash_bytes("ruby-type-flow", b"ruby-type-flow-open-runtime-v4")
            .expect("adapter name is non-empty")
    }

    fn constructed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> ClassSeed {
        let callee = procedure
            .semantics()
            .value(call.callee)
            .expect("a call site's callee value is retained");
        let Some(file) = procedure
            .semantics()
            .source_mapping(callee.source)
            .and_then(|mapping| file_for_locator(workspace, &mapping.locator))
        else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(method) = node_at_mapping(&prepared, procedure, callee.source) else {
            return ClassSeed::NotApplicable;
        };
        let Some(construction) = method.parent().filter(|parent| {
            parent.kind() == "call"
                && parent
                    .child_by_field_name("method")
                    .is_some_and(|candidate| candidate.id() == method.id())
        }) else {
            return ClassSeed::NotApplicable;
        };
        let Some(receiver) = construction
            .child_by_field_name("receiver")
            .filter(|receiver| matches!(receiver.kind(), "constant" | "scope_resolution"))
        else {
            return ClassSeed::NotApplicable;
        };
        if method.utf8_text(prepared.source().as_bytes()).ok() != Some("new") {
            return ClassSeed::NotApplicable;
        }

        match resolve_ruby_bounded(
            workspace.analyzer(),
            &file,
            prepared.source(),
            Some(prepared.tree()),
            &reference_site(&file, method, prepared.source()),
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
            None,
        ) {
            BoundedResolution::Exceeded { .. } => {
                return ClassSeed::Unknown(UnknownReason::SemanticBudget);
            }
            BoundedResolution::Cancelled { .. } => {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            }
            BoundedResolution::Complete { value, .. } => {
                if value.status == DefinitionLookupStatus::Ambiguous {
                    return ClassSeed::Unknown(UnknownReason::AmbiguousCallee);
                }
                if value.status != DefinitionLookupStatus::Resolved
                    || value.definitions.iter().any(|definition| {
                        definition.is_function() && definition.identifier() == "new"
                    })
                {
                    return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
                }
            }
        }

        let outcome = resolve_type_at_reference_site_with_budget(
            workspace.analyzer(),
            &file,
            prepared.source(),
            Some(prepared.tree()),
            reference_site(&file, receiver, prepared.source()),
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
        );
        if !ruby_analyzer(workspace).indexed_source_matches(&file, prepared.source()) {
            return ClassSeed::Unknown(UnknownReason::UncertainFlow);
        }
        match outcome.status {
            TypeLookupStatus::ExceededBudget(_) => {
                ClassSeed::Unknown(UnknownReason::SemanticBudget)
            }
            TypeLookupStatus::Ambiguous => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
            TypeLookupStatus::Resolved => match class_seed_from_lookup_types(
                overlay_of(workspace).as_deref(),
                Language::Ruby,
                &outcome.types,
            ) {
                ClassSeed::Class(identity) => ClassSeed::ClassWithOpenBound(identity),
                ClassSeed::ClassWithOpenBound(identity) => ClassSeed::ClassWithOpenBound(identity),
                ClassSeed::Unknown(reason) => ClassSeed::Unknown(reason),
                ClassSeed::Classes(classes) | ClassSeed::ClassesWithOpenBound(classes) => {
                    ClassSeed::ClassesWithOpenBound(classes)
                }
                ClassSeed::NotApplicable => ClassSeed::Unknown(UnknownReason::UnresolvedCall),
            },
            TypeLookupStatus::NoType
            | TypeLookupStatus::UnsupportedLanguage
            | TypeLookupStatus::InvalidLocation
            | TypeLookupStatus::NotFound => ClassSeed::Unknown(UnknownReason::UnresolvedCall),
        }
    }

    fn constant_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        let Some(file) = procedure
            .semantics()
            .source_mapping(value.source)
            .and_then(|mapping| file_for_locator(workspace, &mapping.locator))
        else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_mapping(&prepared, procedure, value.source) else {
            return ClassSeed::NotApplicable;
        };
        let name = match node.kind() {
            "integer" => "Integer",
            "float" => "Float",
            "rational" => "Rational",
            "complex" => "Complex",
            "true" => "TrueClass",
            "false" => "FalseClass",
            "nil" => "NilClass",
            "simple_symbol" | "hash_key_symbol" | "bare_symbol" => "Symbol",
            "character" => "String",
            "constant" => return ClassSeed::Unknown(UnknownReason::OpenTypeBound),
            _ => return ClassSeed::NotApplicable,
        };
        open_external_seed(workspace, name)
    }

    fn retained_value_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        if value.kind == SemanticValueKind::Callable {
            return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
        }
        if value.kind != SemanticValueKind::Temporary {
            return if value.kind == SemanticValueKind::Exception {
                ClassSeed::Unknown(UnknownReason::OpenTypeBound)
            } else {
                ClassSeed::NotApplicable
            };
        }
        let Some(file) = procedure
            .semantics()
            .source_mapping(value.source)
            .and_then(|mapping| file_for_locator(workspace, &mapping.locator))
        else {
            return ClassSeed::NotApplicable;
        };
        let prepared = match prepared_for_procedure(workspace, procedure, &file) {
            Ok(prepared) => prepared,
            Err(reason) => return ClassSeed::Unknown(reason),
        };
        let Some(node) = node_at_mapping(&prepared, procedure, value.source) else {
            return ClassSeed::NotApplicable;
        };
        match node.kind() {
            "string" | "string_content" => open_external_seed(workspace, "String"),
            "array" => open_external_seed(workspace, "Array"),
            "hash" => open_external_seed(workspace, "Hash"),
            // Exact unmodeled expressions can be runtime data origins. Seed
            // the uncertainty even when the value also has modeled incoming
            // flow; an extra open atom is conservative, while dropping a
            // lambda, range, regexp, or constant reference is unsound.
            _ => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        }
    }

    fn allocation_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _allocation: &AllocationSite,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }

    fn declared_parameter_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _ordinal: u32,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }

    fn accessed_member(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        site: MemberAccessQuery<'_>,
    ) -> Option<Box<str>> {
        let locator = match site {
            MemberAccessQuery::Call(call) => {
                let callee = procedure.semantics().value(call.callee)?;
                let mapping = procedure.semantics().source_mapping(callee.source)?;
                (mapping.kind == SourceMappingKind::Exact).then_some(&mapping.locator)?
            }
            MemberAccessQuery::Load(location) => {
                let MemoryLocationKind::Field { member, .. } = &location.kind else {
                    return None;
                };
                member
            }
        };
        let file = file_for_locator(workspace, locator)?;
        let prepared = prepared_for_procedure(workspace, procedure, &file).ok()?;
        let span = locator.anchor().span();
        let node = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(
                span.start_byte() as usize,
                span.end_byte() as usize,
            )?;
        node.utf8_text(prepared.source().as_bytes())
            .ok()
            .filter(|name| !name.is_empty())
            .map(Box::from)
    }

    fn member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        kind: MemberAccessKind,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberLookup {
        match class {
            ClassIdentity::Workspace(unit) => workspace_member_lookup(workspace, unit, member),
            ClassIdentity::External { symbol_id, .. } => overlay_of(workspace)
                .map(|overlay| external_member_lookup(&overlay, kind, symbol_id, member))
                .unwrap_or(MemberLookup::Unknown(UnknownReason::ExternalNotModeled)),
        }
    }

    fn enclosing_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        let locator = procedure.semantics().locator();
        let file = file_for_locator(workspace, locator)?;
        let mut unit = workspace
            .analyzer()
            .enclosing_code_unit(&file, &analyzer_range_for_span(locator.anchor().span()))?;
        loop {
            if unit.is_class() {
                return Some(ClassIdentity::Workspace(unit));
            }
            unit = workspace.analyzer().parent_of(&unit)?;
        }
    }

    fn class_hierarchy(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
    ) -> ClassHierarchy {
        let ClassIdentity::Workspace(unit) = class else {
            return ClassHierarchy::unknown();
        };
        if current_prepared(workspace, unit.source()).is_none() {
            return ClassHierarchy::unknown();
        }
        let ruby = ruby_analyzer(workspace);
        let ancestors = ruby.get_ancestors(unit);
        if ancestors
            .iter()
            .any(|ancestor| current_prepared(workspace, ancestor.source()).is_none())
        {
            return ClassHierarchy::unknown();
        }
        ClassHierarchy {
            ancestors: ancestors
                .into_iter()
                .map(ClassIdentity::Workspace)
                .collect(),
            descendants: None,
            unresolved_base: false,
            dynamic_attributes: true,
        }
    }
}
