//! Conservative Ruby class-set adapter.
//!
//! Ruby classes and member surfaces remain open at run time. This adapter
//! therefore retains useful class and positive-member evidence together with
//! an explicit open bound, and never proves member absence.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_ruby::graph::RubyGraphSource;
use brokk_bifrost_ruby::graph::resolver::{ReceiverMode, ReceiverType, RubySemanticIndex};
use tree_sitter::Node;

use crate::analyzer::ruby::RubyAnalyzer;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::ClassHierarchy;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::ClassIdentity;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::ClassSeed;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::ExternalClassCache;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::ExternalMemberDeclaration;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::MemberAccessKind;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::MemberAccessQuery;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::MemberDeclaration;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::MemberLookup;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::TypeFlowAdapter;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::UnknownReason;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::accessed_member_locator;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::class_seed_from_lookup_types;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::external_class_identity;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;

use brokk_bifrost_analysis::analyzer::semantic::ids::AdapterSemanticsVersion;

use brokk_bifrost_analysis::analyzer::semantic::ir::model::AllocationSite;

use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::ProcedureHandle;

use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticCallSite;

use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValue;

use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValueKind;

use brokk_bifrost_analysis::analyzer::semantic::ir::model::SourceMappingKind;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::semantic_model_callable_family_id;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use crate::analyzer::usages::get_definition::ruby::resolve_ruby_bounded;

use crate::analyzer::usages::get_definition::ruby::ruby_modeled_result_class_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_type::resolve_type_at_reference_site_with_budget;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::path_utils::rel_path_string;

pub struct RubyTypeFlowAdapter;

fn ruby_analyzer(workspace: &WorkspaceAnalyzer) -> &RubyAnalyzer {
    resolve_analyzer::<RubyAnalyzer>(workspace.analyzer())
        .expect("RubyTypeFlowAdapter serves only workspaces that analyze Ruby")
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
    let prepared = prepared_for(workspace, file);
    brokk_bifrost_analysis::analyzer::semantic::type_flow::current_indexed_prepared(
        prepared,
        |prepared| ruby_analyzer(workspace).indexed_source_matches(file, prepared.source()),
    )
}

fn prepared_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    brokk_bifrost_analysis::analyzer::semantic::type_flow::prepared_syntax_for_procedure(
        workspace,
        procedure,
        file,
        prepared_for(workspace, file),
    )
}

fn node_at_mapping<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    procedure: &ProcedureHandle,
    source: brokk_bifrost_analysis::analyzer::semantic::ids::SourceMappingId,
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
    let range = brokk_bifrost_core::analyzer::model::Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    brokk_bifrost_analysis::analyzer::usages::common::build_reference_site(
        rel_path_string(file),
        node.utf8_text(source.as_bytes())
            .expect("a prepared tree spans its own UTF-8 source")
            .to_owned(),
        range,
        node.start_byte(),
        node.end_byte(),
    )
}

fn open_external_seed(workspace: &WorkspaceAnalyzer, name: &str) -> ClassSeed {
    let mut cache = ExternalClassCache::default();
    external_class_identity(
        workspace.analyzer().semantic_model_overlay().as_deref(),
        Language::Ruby,
        name,
        None,
        &mut cache,
    )
    .map(ClassSeed::ClassWithOpenBound)
    .unwrap_or(ClassSeed::Unknown(UnknownReason::ExternalNotModeled))
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
    let definitions = |consume: &mut dyn FnMut(
        &dyn brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup,
    )| {
        consume(&lookup);
    };
    let scope = AnalyzerQueryScope::new(workspace.analyzer());
    let attribution = brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(
        workspace.analyzer(),
    );
    let semantic = RubySemanticIndex::build_for_lookup(
        RubyGraphSource {
            attribution: &attribution,
            token: scope.token(),
            index: workspace.analyzer(),
            definitions: &definitions,
        },
        ruby,
    );
    let Some(visible) = semantic.visible_files_from(class.source()) else {
        return MemberLookup::Unknown(UnknownReason::UncertainFlow);
    };
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
    brokk_bifrost_analysis::analyzer::semantic::type_flow::present_member(
        MemberDeclaration::Workspace(declaration),
    )
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
    brokk_bifrost_analysis::analyzer::semantic::type_flow::present_member(
        MemberDeclaration::External(ExternalMemberDeclaration::new(
            records
                .into_iter()
                .map(|record| Box::from(record.id.as_str())),
        )),
    )
}

impl TypeFlowAdapter for RubyTypeFlowAdapter {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn semantics_version(&self) -> AdapterSemanticsVersion {
        AdapterSemanticsVersion::hash_bytes(
            "ruby-type-flow",
            b"ruby-type-flow-open-runtime-same-name-external-class-records-trivia-covered-reference-sites-v8",
        )
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

        match ruby_modeled_result_class_bounded(
            workspace.analyzer(),
            &file,
            prepared.source(),
            prepared.tree(),
            construction,
            INTERACTIVE_TYPE_LOOKUP_BUDGET,
            None,
        ) {
            BoundedResolution::Complete {
                value: Some(class), ..
            } => {
                return if ruby_analyzer(workspace).indexed_source_matches(&file, prepared.source())
                {
                    ClassSeed::ClassWithOpenBound(class)
                } else {
                    ClassSeed::Unknown(UnknownReason::UncertainFlow)
                };
            }
            BoundedResolution::Complete { value: None, .. } => {}
            BoundedResolution::Exceeded { .. } => {
                return ClassSeed::Unknown(UnknownReason::SemanticBudget);
            }
            BoundedResolution::Cancelled { .. } => {
                return ClassSeed::Unknown(UnknownReason::UncertainFlow);
            }
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
            TypeLookupStatus::InvalidLocation => {
                debug_assert!(false, "invalid internal type reference site: {outcome:?}");
                ClassSeed::Unknown(UnknownReason::UncertainFlow)
            }
            TypeLookupStatus::Unavailable => ClassSeed::Unknown(UnknownReason::UncertainFlow),
            TypeLookupStatus::Incomplete | TypeLookupStatus::Cancelled => {
                ClassSeed::Unknown(UnknownReason::UncertainFlow)
            }
            TypeLookupStatus::ExceededBudget(_) => {
                ClassSeed::Unknown(UnknownReason::SemanticBudget)
            }
            TypeLookupStatus::Ambiguous => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
            TypeLookupStatus::Resolved => match class_seed_from_lookup_types(
                workspace.analyzer().semantic_model_overlay().as_deref(),
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
            // A constant read, with or without an explicit owner path, may
            // denote any class: the IR keeps the constant object itself, not
            // the type of the value it holds, so its class stays open.
            "constant" | "scope_resolution" => {
                return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
            }
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
        // Ruby scalar literals carry their exact payload for the
        // contradictory-condition consumer. The type-flow planner (and
        // direct adapter clients) can therefore reach this retained-value
        // hook instead of `constant_class`; preserve the existing literal
        // class seed by reusing the exact mapping there.
        if matches!(
            value.kind,
            SemanticValueKind::Boolean(_)
                | SemanticValueKind::SignedInteger(_)
                | SemanticValueKind::UnsignedInteger(_)
        ) {
            return self.constant_class(workspace, procedure, value);
        }
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
        let locator = accessed_member_locator(procedure, site)?;
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
            ClassIdentity::External { symbol_id, .. } => workspace
                .analyzer()
                .semantic_model_overlay()
                .map(|overlay| external_member_lookup(&overlay, kind, symbol_id, member))
                .unwrap_or(MemberLookup::Unknown(UnknownReason::ExternalNotModeled)),
            ClassIdentity::Intrinsic { .. } => {
                MemberLookup::Unknown(UnknownReason::ExternalNotModeled)
            }
        }
    }

    fn enclosing_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        let locator = procedure.semantics().locator();
        let file = file_for_locator(workspace, locator)?;
        brokk_bifrost_analysis::analyzer::semantic::type_flow::enclosing_workspace_class_unit(
            workspace.analyzer(),
            &file,
            locator.anchor().span(),
            |_| true,
        )
        .map(ClassIdentity::Workspace)
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
        let ancestors = ruby.get_ancestors(unit).definite().to_vec();
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
