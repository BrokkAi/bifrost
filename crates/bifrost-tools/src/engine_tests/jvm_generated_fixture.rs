use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::Language;
use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredResolutionFragment;
use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionIdentityCatalog;
use brokk_bifrost_analysis::analyzer::resolution::{
    BindingFragmentId, EndpointSignature, ResolutionCompletion, ResolutionIncompleteReason,
    StackPattern, StackVariableId, WitnessStep,
};

use brokk_bifrost_analysis::analyzer::resolution::{
    BindingNodeId, CandidatePathIdentity, PartialPath, SemanticId,
};

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountRecord;

use brokk_bifrost_analysis::analyzer::store::resolution_stage::lexical_readers;
use rusqlite::Connection;

use brokk_bifrost_analysis::analyzer::resolution::local_identity::{
    ResolutionLookupSemanticRecipe, SelectedResolutionMountOrdinal,
};

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory;

use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionScopeId};
use brokk_bifrost_core::analyzer::rust_facts::{
    RustCfgCondition, RustImportTargetFact, RustVisibility,
};

use brokk_bifrost_core::analyzer::source_facts::SourceImportId;

#[doc(hidden)]
pub const BASE: u32 = 1 << 31;

#[doc(hidden)]
pub fn host(
    selection: &SelectedResolutionMountInventory<'_>,
    ordinal: u32,
) -> std::sync::Arc<SelectedResolutionMountRecord> {
    selection
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))
        .unwrap()
}

#[doc(hidden)]
pub fn snapshot(connection: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "producers",
        "nodes",
        "node_owners",
        "paths",
        "semantic_coordinates",
        "node_coordinates",
        "path_coordinates",
        "variable_coordinates",
        "recipes",
        "allocation_counters",
    ]
    .into_iter()
    .map(|family| {
        let mut statement = connection
            .prepare(&format!(
                "SELECT * FROM temp.selected_resolution_stage_{family} ORDER BY 1,2"
            ))
            .unwrap();
        let width = statement.column_count();
        statement
            .query_map([], |row| (0..width).map(|index| row.get(index)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

// SQL storage alpha-normalizes variables per path. The model key retains
// exact endpoint identities and variable aliasing across both endpoint stacks;
// the allocation ceiling is derived metadata, not part of that behavior.
#[doc(hidden)]
pub fn assert_path_body(actual: &PartialPath, expected: &PartialPath) {
    brokk_bifrost_analysis::analyzer::store::resolution_stage::assert_partial_path_bodies_equal(
        actual, expected,
    );
}

#[doc(hidden)]
pub fn assert_paths(
    selection: &SelectedResolutionMountInventory<'_>,
    fragments: &[LoweredResolutionFragment],
) {
    let expected = fragments
        .iter()
        .flat_map(|fragment| {
            fragment.paths().iter().map(|(path, body)| {
                (
                    CandidatePathIdentity::new(fragment.fragment(), *path),
                    body.clone(),
                )
            })
        })
        .collect::<Vec<_>>();
    let keys = expected.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    let actual =
        lexical_readers::hydrate_candidate_paths(selection, &keys, &CancellationToken::new())
            .unwrap()
            .unwrap();
    assert_eq!(actual.len(), expected.len());
    for (actual, (identity, expected)) in actual.iter().zip(&expected) {
        let actual = actual
            .as_ref()
            .unwrap_or_else(|| panic!("missing path {identity:?}"));
        assert_path_body(actual, expected);
    }
}

#[doc(hidden)]
pub fn original_path(end: BindingNodeId, reason: u64) -> PartialPath {
    let variable = StackVariableId::operation_local((1 << 53) + 11);
    let semantic = SemanticId::context_local((1 << 53) + 12);
    PartialPath::new(
        EndpointSignature::new(
            BindingNodeId::context_local((1 << 53) + 13),
            StackPattern::open(vec![semantic], variable),
            StackPattern::closed([]),
        ),
        EndpointSignature::new(
            end,
            StackPattern::open(vec![semantic], variable),
            StackPattern::closed([]),
        ),
        Vec::new(),
        vec![WitnessStep::Node(end)],
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
            SemanticId::context_local(reason),
        )]),
    )
}

#[doc(hidden)]
pub fn glob(
    selection: &SelectedResolutionMountInventory<'_>,
    name: &str,
    module: &[&str],
) -> (LoweredResolutionFragment, ResolutionIdentityCatalog) {
    let import = RustImportTargetFact {
        native_scope: Some(ResolutionScopeId::new(91)),
        source_import_id: Some(SourceImportId::new(92)),
        module_path: module.iter().map(|segment| (*segment).to_owned()).collect(),
        bound_name: None,
        imported_name: None,
        is_glob: true,
        leading_absolute: false,
        is_extern_crate: false,
        is_macro_use: false,
        visibility: RustVisibility::Private,
        cfg_condition: RustCfgCondition::Always,
        owner_module: String::new(),
        owner_start: 0,
        owner_end: 20,
        local_extent: None,
        source_occurrences: None,
    };
    LoweredResolutionFragment::selected_include_glob(
        BindingFragmentId::at_ordinal(0),
        &selection
            .shared_name_table()
            .interner(selection.connection()),
        &import,
        &ResolutionLookupSemanticRecipe::new(Language::Rust, ResolutionNamespace::Value, name),
    )
}
