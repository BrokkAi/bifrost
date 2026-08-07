//! The analyzer-bound half of [`brokk_bifrost_cpp::graph::resolver`]'s tests.
//!
//! They build real `CppAnalyzer`/`WorkspaceAnalyzer` fixtures and assert on the
//! resolver's interior memo counters, so they cannot follow the resolver across
//! the crate line -- the C++ crate names no analyzer type. The counters they
//! read are `test-support`-gated in the crate and reachable here because this
//! crate's dev-dependency on it turns that feature on.

use crate::analyzer::usages::cpp_graph::CppDispatch;
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, ProjectFile, resolve_analyzer,
};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CppTemplateExpression, CppTemplateParameterMetadata, CppTemplateTerm,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_cpp::declarations::node_text;
use brokk_bifrost_cpp::graph::CppGraphSource;
use brokk_bifrost_cpp::graph::resolver::*;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tree_sitter::{Node, Parser};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use crate::analyzer::usages::cpp_graph::shared::CppAuthoritativeUsageBatch;
    use crate::analyzer::usages::model::FuzzyResult;
    use brokk_bifrost_core::analyzer::model::CppTemplateParameterKind;
    use std::fs;

    fn structured_cpp_unit(
        source: ProjectFile,
        kind: CodeUnitType,
        segments: &[(&str, SegmentKind)],
        signature: Option<&str>,
    ) -> CodeUnit {
        let interner = segment_interner();
        let mut fq = FqName::new();
        for &(text, segment_kind) in segments {
            fq.push(interner.intern(text, segment_kind));
        }
        CodeUnit::from_fq(source, kind, fq, 1, signature.map(str::to_string), false)
    }

    fn template_atom(text: &str) -> CppTemplateExpression {
        CppTemplateExpression {
            text: text.to_string(),
            term: CppTemplateTerm::Atom {
                kind: "type_identifier".to_string(),
                text: text.to_string(),
            },
        }
    }

    fn template_parameter(
        name: &str,
        variadic: bool,
        default: Option<&str>,
    ) -> CppTemplateParameterMetadata {
        CppTemplateParameterMetadata {
            name: name.to_string(),
            kind: CppTemplateParameterKind::Type,
            variadic,
            default: default.map(template_atom),
        }
    }

    fn template_pack_expansion(name: &str) -> CppTemplateExpression {
        CppTemplateExpression {
            text: format!("{name}..."),
            term: CppTemplateTerm::Node {
                kind: "parameter_pack_expansion".to_string(),
                children: vec![
                    CppTemplateTerm::Parameter(name.to_string()),
                    CppTemplateTerm::Atom {
                        kind: "...".to_string(),
                        text: "...".to_string(),
                    },
                ],
            },
        }
    }

    #[test]
    fn template_argument_binding_supports_terminal_parameter_packs() {
        let pack_only = [template_parameter("Args", true, None)];
        for arguments in [
            Vec::new(),
            vec![template_atom("One")],
            vec![template_atom("One"), template_atom("Two")],
        ] {
            let (expanded, bindings) = cpp_bind_template_arguments(&pack_only, &arguments)
                .expect("terminal pack must consume every remaining argument");
            assert_eq!(
                expanded
                    .iter()
                    .map(|argument| argument.text.as_str())
                    .collect::<Vec<_>>(),
                arguments
                    .iter()
                    .map(|argument| argument.text.as_str())
                    .collect::<Vec<_>>()
            );
            assert!(matches!(
                bindings.get("Args"),
                Some(CppTemplateTerm::Node { kind, children })
                    if kind == "parameter_pack" && children.len() == arguments.len()
            ));
        }

        let fixed_and_pack = [
            template_parameter("Head", false, Some("Default")),
            template_parameter("Tail", true, None),
        ];
        let (defaulted, _) = cpp_bind_template_arguments(&fixed_and_pack, &[])
            .expect("the fixed default must precede an empty pack");
        assert_eq!(defaulted[0].text, "Default");
        let (many, bindings) = cpp_bind_template_arguments(
            &fixed_and_pack,
            &[
                template_atom("Head"),
                template_atom("One"),
                template_atom("Two"),
            ],
        )
        .expect("fixed parameter plus trailing pack");
        assert_eq!(many.len(), 3);
        assert!(matches!(
            bindings.get("Tail"),
            Some(CppTemplateTerm::Node { children, .. }) if children.len() == 2
        ));

        assert!(
            cpp_bind_template_arguments(&[template_parameter("Only", false, None)], &[]).is_none(),
            "a missing fixed argument without a default must fail"
        );
        assert!(
            cpp_bind_template_arguments(
                &[template_parameter("Only", false, None)],
                &[template_atom("One"), template_atom("Extra")],
            )
            .is_none(),
            "extra arguments without a pack must fail"
        );
        assert!(
            cpp_bind_template_arguments(
                &[
                    template_parameter("Pack", true, None),
                    template_parameter("Trailing", false, Some("Default")),
                ],
                &[template_atom("One")],
            )
            .is_none(),
            "a non-terminal pack is ambiguous and must fail closed"
        );
    }

    #[test]
    fn template_alias_target_expands_bound_parameter_packs() {
        let parameters = [
            template_parameter("Head", false, None),
            template_parameter("Tail", true, None),
        ];
        for arguments in [
            vec![template_atom("Head")],
            vec![template_atom("Head"), template_atom("One")],
            vec![
                template_atom("Head"),
                template_atom("One"),
                template_atom("Two"),
            ],
        ] {
            let (_, bindings) = cpp_bind_template_arguments(&parameters, &arguments)
                .expect("a fixed parameter and terminal pack must bind");
            let expanded = cpp_substitute_template_arguments(
                &[template_atom("Head"), template_pack_expansion("Tail")],
                &bindings,
            )
            .expect("a root pack expansion must flatten into target arguments");
            assert_eq!(
                expanded
                    .iter()
                    .map(|argument| &argument.term)
                    .collect::<Vec<_>>(),
                arguments
                    .iter()
                    .map(|argument| &argument.term)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn type_target_spec_scan_keys_collapse_logical_redeclarations() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let logical_type = |path: &str| {
            CodeUnit::with_signature(
                ProjectFile::new(root.clone(), path),
                CodeUnitType::Class,
                "gfx",
                "Size",
                Some("class Size".to_string()),
                false,
            )
        };
        let first_type = logical_type("first.h");
        let duplicate_type = logical_type("duplicate.h");
        let first_type_spec = TargetSpec::new(
            first_type.clone(),
            TargetKind::Type,
            Some(first_type),
            "Size".to_string(),
            None,
            None,
        );
        let duplicate_type_spec = TargetSpec::new(
            duplicate_type.clone(),
            TargetKind::Type,
            Some(duplicate_type),
            "Size".to_string(),
            None,
            None,
        );
        assert_eq!(
            first_type_spec.type_scan_key(),
            duplicate_type_spec.type_scan_key()
        );

        let divergent_signature = CodeUnit::with_signature(
            ProjectFile::new(root.clone(), "definition.h"),
            CodeUnitType::Class,
            "gfx",
            "Size",
            Some("<typename Value>".to_string()),
            false,
        );
        let divergent_signature_spec = TargetSpec::new(
            divergent_signature.clone(),
            TargetKind::Type,
            Some(divergent_signature),
            "Size".to_string(),
            None,
            None,
        );
        assert_ne!(
            first_type_spec.type_scan_key(),
            divergent_signature_spec.type_scan_key(),
            "#803 requires each divergent physical target spec to remain independently scanned"
        );

        let other_namespace = CodeUnit::with_signature(
            ProjectFile::new(root, "other_namespace.h"),
            CodeUnitType::Class,
            "other",
            "Size",
            Some("class Size".to_string()),
            false,
        );
        let other_namespace_spec = TargetSpec::new(
            other_namespace.clone(),
            TargetKind::Type,
            Some(other_namespace),
            "Size".to_string(),
            None,
            None,
        );
        assert_ne!(
            first_type_spec.type_scan_key(),
            other_namespace_spec.type_scan_key(),
            "same-short-name Types with distinct FQNs must retain separate scans"
        );
    }

    #[test]
    fn alternate_same_fqn_type_candidates_require_one_source_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let source_location = root.join("source_location.h");
        let consumer = root.join("consumer.cpp");
        let other_header = root.join("other_source_location.h");
        let other_namespace = root.join("other_namespace.h");
        fs::write(
            &source_location,
            r#"#pragma once
namespace absl {
#if defined(ABSL_USES_STD_SOURCE_LOCATION) && defined(ABSL_HAVE_STD_SOURCE_LOCATION)
ABSL_NAMESPACE_BEGIN
using SourceLocation = std::source_location;
ABSL_NAMESPACE_END
#else
ABSL_NAMESPACE_BEGIN
class SourceLocation {};
ABSL_NAMESPACE_END
#endif
}

"#,
        )
        .expect("write source-location fixture");
        fs::write(
            &consumer,
            "#include \"source_location.h\"\nvoid Use(absl::SourceLocation loc) {}\n",
        )
        .expect("write consumer fixture");
        fs::write(
            &other_header,
            "namespace absl {\n#if defined(OTHER)\nclass SourceLocation {};\n#endif\n}\n",
        )
        .expect("write duplicate source fixture");
        fs::write(
            &other_namespace,
            "namespace other {\n#if defined(OTHER)\nusing SourceLocation = int;\n#endif\n}\n",
        )
        .expect("write distinct-namespace fixture");
        let analyzer = CppAnalyzer::from_project(crate::analyzer::TestProject::new(
            root.clone(),
            crate::analyzer::Language::Cpp,
        ));
        let source_location = ProjectFile::new(root.clone(), "source_location.h");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let declarations = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| {
                unit.kind() == CodeUnitType::Class
                    && unit.fq_name() == "absl.SourceLocation"
                    && unit.source() == &source_location
            })
            .collect::<Vec<_>>();
        assert_eq!(
            declarations.len(),
            2,
            "conditional class/alias declarations"
        );
        let class_decl = declarations
            .iter()
            .find(|unit| unit.signature().is_none())
            .expect("fallback class declaration");
        let alias_decl = declarations
            .iter()
            .find(|unit| {
                unit.signature()
                    .is_some_and(|signature| signature.starts_with("using"))
            })
            .expect("standard-library alias declaration");
        let roots = HashSet::from_iter([consumer.clone()]);
        let visibility =
            VisibilityIndex::build(&analyzer, &CppGraphSource::from_source(&analyzer), &roots);
        assert_eq!(
            visibility.unique_type_candidate_preserving_target(
                &CppGraphSource::from_source(&analyzer),
                &consumer,
                &[class_decl, alias_decl],
                class_decl,
            ),
            Some((*class_decl).clone()),
            "same-file conditional declarations preserve the selected target identity"
        );
        assert!(visibility.alternate_same_fqn_type_declarations(
            &CppGraphSource::from_source(&analyzer),
            &[class_decl, alias_decl],
            class_decl,
        ));
        assert!(visibility.complementary_same_fqn_type_declarations(
            &CppGraphSource::from_source(&analyzer),
            &[class_decl, alias_decl],
            class_decl,
        ));
        let unguarded_duplicate = CodeUnit::with_signature(
            source_location.clone(),
            CodeUnitType::Class,
            "absl",
            "SourceLocation",
            Some("using SourceLocation = int;".to_string()),
            false,
        );
        assert!(
            !visibility.alternate_same_fqn_type_declarations(
                &CppGraphSource::from_source(&analyzer),
                &[class_decl, alias_decl, &unguarded_duplicate],
                class_decl,
            ),
            "every candidate pair must be mutually exclusive"
        );

        let duplicate = CodeUnit::with_signature(
            ProjectFile::new(root.clone(), "other_source_location.h"),
            CodeUnitType::Class,
            "absl",
            "SourceLocation",
            Some("class SourceLocation".to_string()),
            false,
        );
        assert!(!visibility.alternate_same_fqn_type_declarations(
            &CppGraphSource::from_source(&analyzer),
            &[class_decl, &duplicate],
            class_decl,
        ));
        let other_namespace_decl = CodeUnit::with_signature(
            source_location.clone(),
            CodeUnitType::Class,
            "other",
            "SourceLocation",
            Some("using SourceLocation = std::source_location;".to_string()),
            false,
        );
        assert!(!visibility.alternate_same_fqn_type_declarations(
            &CppGraphSource::from_source(&analyzer),
            &[class_decl, &other_namespace_decl],
            class_decl,
        ));
    }

    #[test]
    fn const_global_with_extern_peer_remains_external_with_exact_fqn_peer_bound() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let write = |path: &str, contents: &str| {
            let full = root.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).expect("create parent directories");
            }
            fs::write(&full, contents).expect("write fixture");
            ProjectFile::new(root.clone(), path)
        };
        let _header = write(
            "shared.hpp",
            "#pragma once\nextern const int shared_value;\n",
        );
        let definition = write(
            "definition.cpp",
            "#include \"shared.hpp\"\nconst int shared_value = 0;\n",
        );
        for index in 0..32 {
            let path = format!("noise_{index}.cpp");
            let source = format!("const int unrelated_{index} = {index};\n");
            let _ = write(&path, &source);
        }
        let analyzer = CppAnalyzer::from_project(crate::analyzer::TestProject::new(
            root,
            crate::analyzer::Language::Cpp,
        ));
        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| {
                unit.kind() == CodeUnitType::Field
                    && unit.identifier() == "shared_value"
                    && unit.source() == &definition
            })
            .expect("definition global field");
        analyzer.reset_full_hydration_count_for_test();
        let (internal, inspected_peers) =
            with_cpp_global_field_linkage_peer_inspection_counter_for_test(|| {
                cpp_global_field_has_internal_linkage(
                    &CppGraphSource::from_source(&analyzer),
                    &target,
                )
            });

        assert!(
            !internal,
            "an extern peer in the exact-fqn bucket must keep the const definition externally visible"
        );
        assert_eq!(
            inspected_peers, 1,
            "exact-fqn peer lookup should inspect only the matching extern peer, not unrelated globals from the rest of the workspace"
        );
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted field linkage must avoid preparing source syntax during global-field resolution"
        );
    }

    #[test]
    fn visibility_build_hydrates_overlapping_closures_once_and_preserves_root_visibility() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let left = ProjectFile::new(root.clone(), "left.cpp");
        let right = ProjectFile::new(root.clone(), "right.cpp");
        let shared = ProjectFile::new(root.clone(), "shared.h");
        let leaf = ProjectFile::new(root.clone(), "leaf.h");
        let right_only = ProjectFile::new(root, "right_only.h");

        let adjacency = HashMap::from_iter([
            (left.clone(), vec![shared.clone()]),
            (right.clone(), vec![shared.clone(), right_only.clone()]),
            (shared.clone(), vec![leaf.clone()]),
            (leaf.clone(), Vec::new()),
            (right_only.clone(), Vec::new()),
        ]);
        let declarations_by_file: HashMap<_, _> = [
            (left.clone(), "Left"),
            (right.clone(), "Right"),
            (shared.clone(), "Shared"),
            (leaf.clone(), "Leaf"),
            (right_only.clone(), "RightOnly"),
        ]
        .into_iter()
        .map(|(file, name)| {
            let declaration = CodeUnit::new(file.clone(), CodeUnitType::Class, "", name);
            (file, BTreeSet::from([declaration]))
        })
        .collect();

        let roots = HashSet::from_iter([left.clone(), right.clone()]);
        let mut include_discovery_counts = HashMap::<ProjectFile, usize>::default();
        let VisibilityData {
            visible_by_file, ..
        } = build_visibility_data(
            &roots,
            None,
            |file| {
                *include_discovery_counts.entry(file.clone()).or_default() += 1;
                adjacency.get(file).cloned().unwrap_or_default()
            },
            |file| declarations_by_file.get(file).cloned().unwrap_or_default(),
        );

        assert_eq!(include_discovery_counts.len(), adjacency.len());
        assert!(
            include_discovery_counts.values().all(|count| *count == 1),
            "the complete visibility build must discover each union-closure file exactly once: \
             {include_discovery_counts:#?}"
        );
        assert_eq!(include_discovery_counts.get(&shared), Some(&1));
        assert_eq!(include_discovery_counts.get(&leaf), Some(&1));

        let visible_names = |root: &ProjectFile| {
            visible_by_file
                .get(root)
                .into_iter()
                .flatten()
                .map(|unit| unit.identifier().to_string())
                .collect::<HashSet<_>>()
        };

        assert_eq!(
            visible_names(&left),
            HashSet::from_iter(["Left", "Shared", "Leaf"].map(str::to_string))
        );
        assert_eq!(
            visible_names(&right),
            HashSet::from_iter(["Right", "Shared", "Leaf", "RightOnly"].map(str::to_string))
        );
    }

    #[test]
    fn union_visibility_keeps_colliding_declarations_root_local() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let left = ProjectFile::new(root.clone(), "left.cpp");
        let right = ProjectFile::new(root.clone(), "right.cpp");
        let left_header = ProjectFile::new(root.clone(), "left/collision.h");
        let right_header = ProjectFile::new(root, "right/collision.h");
        let left_collision =
            CodeUnit::new(left_header.clone(), CodeUnitType::Class, "", "Collision");
        let right_collision =
            CodeUnit::new(right_header.clone(), CodeUnitType::Class, "", "Collision");
        let adjacency = HashMap::from_iter([
            (left.clone(), vec![left_header.clone()]),
            (right.clone(), vec![right_header.clone()]),
            (left_header.clone(), Vec::new()),
            (right_header.clone(), Vec::new()),
        ]);
        let declarations = HashMap::from_iter([
            (left_header.clone(), BTreeSet::from([left_collision])),
            (right_header.clone(), BTreeSet::from([right_collision])),
        ]);
        let roots = HashSet::from_iter([left.clone(), right.clone()]);
        let VisibilityData {
            visible_by_file, ..
        } = build_visibility_data(
            &roots,
            None,
            |file| adjacency.get(file).cloned().unwrap_or_default(),
            |file| declarations.get(file).cloned().unwrap_or_default(),
        );
        let cpp = visibility_analyzer(&visible_by_file);
        let visibility = visibility_index(&cpp, visible_by_file);
        let candidate_sources = |file: &ProjectFile| {
            visibility
                .visible_identifier_candidates(file, "Collision")
                .map(|candidate| candidate.source().clone())
                .collect::<HashSet<_>>()
        };

        assert_eq!(candidate_sources(&left), HashSet::from_iter([left_header]));
        assert_eq!(
            candidate_sources(&right),
            HashSet::from_iter([right_header])
        );
    }

    #[test]
    fn shared_authoritative_batch_keeps_same_named_anonymous_namespace_globals_root_local() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let left = ProjectFile::new(root.clone(), "left.cpp");
        let right = ProjectFile::new(root.clone(), "right.cpp");
        let left_source = "namespace {\nconstexpr int local_value = 1;\n}\nint read_left() { return local_value; }\n";
        let right_source = "namespace {\nconstexpr int local_value = 2;\n}\nint read_right() { return local_value; }\n";
        fs::write(root.join("left.cpp"), left_source).expect("write left fixture");
        fs::write(root.join("right.cpp"), right_source).expect("write right fixture");
        let cpp = CppAnalyzer::from_project(crate::analyzer::TestProject::new(
            root.clone(),
            crate::analyzer::Language::Cpp,
        ));
        let target_for = |source: &ProjectFile| {
            cpp.get_all_declarations()
                .into_iter()
                .find(|unit| {
                    unit.kind() == CodeUnitType::Field
                        && unit.identifier() == "local_value"
                        && unit.source() == source
                })
                .expect("fixture global field declaration")
        };
        let left_global = target_for(&left);
        let right_global = target_for(&right);
        let roots = HashSet::from_iter([left.clone(), right.clone()]);
        let batch = CppAuthoritativeUsageBatch::new(&cpp, &roots).expect("shared cpp batch");
        let candidate_files = HashSet::from_iter([left.clone(), right.clone()]);
        let expected_hit = |file: &ProjectFile, source: &str| {
            let start = source.rfind("local_value;").expect("usage marker");
            (file.clone(), start, start + "local_value".len())
        };
        let hit_ranges = |result: FuzzyResult| match result {
            FuzzyResult::Success {
                hits_by_overload, ..
            } => hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| (hit.file, hit.start_offset, hit.end_offset))
                .collect::<HashSet<_>>(),
            other => panic!("expected shared authoritative success, got {other:?}"),
        };
        let left_hits = hit_ranges(
            batch
                .find_usages(std::slice::from_ref(&left_global), &candidate_files, 1000)
                .into_fuzzy_result(),
        );
        let right_hits = hit_ranges(
            batch
                .find_usages(std::slice::from_ref(&right_global), &candidate_files, 1000)
                .into_fuzzy_result(),
        );

        assert_eq!(
            left_hits,
            HashSet::from_iter([expected_hit(&left, left_source)]),
        );
        assert_eq!(
            right_hits,
            HashSet::from_iter([expected_hit(&right, right_source)]),
        );

        let visibility = VisibilityIndex::build(&cpp, &CppGraphSource::from_source(&cpp), &roots);
        assert!(visibility.is_visible(&left, &left_global));
        assert!(visibility.is_visible(&right, &right_global));
        assert!(
            !visibility.is_visible(&left, &right_global),
            "shared authoritative visibility must not treat a sibling anonymous-namespace global as visible by logical name alone"
        );
        assert!(
            !visibility.is_visible(&right, &left_global),
            "shared authoritative visibility must not treat a sibling anonymous-namespace global as visible by logical name alone"
        );
    }

    #[test]
    fn visible_identifier_index_skips_linkage_for_reachable_field_sources() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let left = ProjectFile::new(root.clone(), "left.cpp");
        let right = ProjectFile::new(root.clone(), "right.cpp");
        let shared = ProjectFile::new(root.clone(), "shared.h");
        let local = CodeUnit::new(shared.clone(), CodeUnitType::Field, "", "local_value");
        let external = CodeUnit::new(shared.clone(), CodeUnitType::Field, "", "shared_value");
        let visible = HashSet::from_iter([local.clone(), external.clone()]);
        let visible_by_file =
            HashMap::from_iter([(left.clone(), visible.clone()), (right.clone(), visible)]);
        let visible_source_files_by_root = HashMap::from_iter([
            (
                left.clone(),
                HashSet::from_iter([left.clone(), local.source().clone()]),
            ),
            (
                right.clone(),
                HashSet::from_iter([right.clone(), local.source().clone()]),
            ),
        ]);
        let cpp = visibility_analyzer(&visible_by_file);
        let (by_identifier, classification_count) =
            with_cpp_global_field_internal_linkage_classification_counter_for_test(|| {
                build_visible_identifier_index(
                    &CppGraphSource::from_source(&cpp),
                    &visible_by_file,
                    &visible_source_files_by_root,
                    &mut HashMap::default(),
                )
            });

        assert_eq!(
            classification_count, 0,
            "a field from a reachable source does not need linkage classification"
        );
        // issue_1184 exercises the authoritative internal-linkage/root-isolation behavior.
        // This fixture only guards that sharing the cache across roots preserves the buckets.
        for root in [&left, &right] {
            let bucket = by_identifier
                .get(root)
                .expect("visible identifier bucket for root");
            assert_eq!(
                bucket
                    .get("local_value")
                    .expect("shared field bucket")
                    .len(),
                1,
                "sharing the classification cache must not change the per-root local_value bucket"
            );
            assert_eq!(
                bucket
                    .get("shared_value")
                    .expect("shared field bucket")
                    .len(),
                1,
                "sharing the classification cache must not change the per-root shared_value bucket"
            );
        }
    }

    /// Owns the analyzer the borrowed index points at; keep it alive for as
    /// long as the returned index is used.
    fn visibility_analyzer(
        visible_by_file: &HashMap<ProjectFile, HashSet<CodeUnit>>,
    ) -> CppAnalyzer {
        let root = visible_by_file
            .keys()
            .next()
            .expect("test visibility needs at least one file")
            .root()
            .to_path_buf();
        CppAnalyzer::new(Arc::new(crate::analyzer::TestProject::new(
            root,
            crate::analyzer::Language::Cpp,
        )))
    }

    fn visibility_index<'a>(
        cpp: &'a CppAnalyzer,
        visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    ) -> VisibilityIndex<'a> {
        VisibilityIndex::from_visible_files_for_test(cpp, visible_by_file)
    }

    #[test]
    fn template_id_without_specialization_metadata_keeps_resolved_primary() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let legacy = CodeUnit::new(
            ProjectFile::new(root, "legacy.h"),
            CodeUnitType::Class,
            "",
            "legacy",
        );
        let visible_by_file =
            HashMap::from_iter([(consumer.clone(), HashSet::from_iter([legacy.clone()]))]);
        let cpp = visibility_analyzer(&visible_by_file);
        let visibility = visibility_index(&cpp, visible_by_file);
        let source = "legacy<int> value;";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("set C++ grammar");
        let tree = parser.parse(source, None).expect("parse template-id");
        let mut stack = vec![tree.root_node()];
        let mut type_node = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "template_type" {
                type_node = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(
            visibility.resolve_type_node_result(
                &consumer,
                type_node.expect("template type node"),
                source,
            ),
            Ok(Some(legacy))
        );
    }

    #[test]
    fn deeply_nested_cpp_template_terms_use_stack_safe_matching_and_substitution() {
        let mut pattern = CppTemplateTerm::Parameter("T".to_string());
        let mut argument = CppTemplateTerm::Atom {
            kind: "primitive_type".to_string(),
            text: "int".to_string(),
        };
        for _ in 0..512 {
            pattern = CppTemplateTerm::Node {
                kind: "template_argument".to_string(),
                children: vec![pattern],
            };
            argument = CppTemplateTerm::Node {
                kind: "template_argument".to_string(),
                children: vec![argument],
            };
        }

        let parameters = std::iter::once("T").collect::<HashSet<_>>();
        let mut bindings = HashMap::default();
        assert!(cpp_unify_template_term(
            &pattern,
            &argument,
            &parameters,
            &mut bindings,
        ));
        let substituted =
            cpp_substitute_template_term(&pattern, &bindings).expect("bound deep template term");
        assert!(cpp_unify_template_term(
            &substituted,
            &argument,
            &HashSet::default(),
            &mut HashMap::default(),
        ));
    }

    #[test]
    fn qualified_type_lookup_inspects_only_exact_fqn_candidates() {
        const UNRELATED_DECLARATIONS: usize = 256;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let target_a_file = ProjectFile::new(root.clone(), "include/target_a.h");
        let target_b_file = ProjectFile::new(root.clone(), "include/target_b.h");
        let target_a = CodeUnit::new(target_a_file, CodeUnitType::Class, "perf", "Exact");
        let target_b = CodeUnit::new(target_b_file, CodeUnitType::Class, "perf", "Exact");
        let same_fqn_function = CodeUnit::with_signature(
            ProjectFile::new(root.clone(), "include/function.h"),
            CodeUnitType::Function,
            "perf",
            "Exact",
            Some("void Exact()".to_string()),
            false,
        );
        let alias = CodeUnit::with_signature(
            ProjectFile::new(root.clone(), "include/alias.h"),
            CodeUnitType::Field,
            "perf",
            "Alias",
            Some("using Alias = Exact;".to_string()),
            false,
        );
        let global = CodeUnit::new(
            ProjectFile::new(root.clone(), "include/global.h"),
            CodeUnitType::Class,
            "",
            "Global",
        );
        let hidden_same_fqn = CodeUnit::new(
            ProjectFile::new(root.clone(), "hidden/target.h"),
            CodeUnitType::Class,
            "perf",
            "Exact",
        );

        let mut visible = HashSet::default();
        for index in 0..UNRELATED_DECLARATIONS {
            visible.insert(CodeUnit::new(
                ProjectFile::new(root.clone(), format!("include/unrelated_{index}.h")),
                CodeUnitType::Class,
                format!("unrelated{index}"),
                format!("Type{index}"),
            ));
        }
        visible.extend([
            target_a.clone(),
            target_b.clone(),
            same_fqn_function.clone(),
            alias.clone(),
            global.clone(),
        ]);
        let visible_by_file = HashMap::from_iter([
            (consumer.clone(), visible.clone()),
            (alias.source().clone(), visible),
        ]);
        let cpp = visibility_analyzer(&visible_by_file);
        let visibility = visibility_index(&cpp, visible_by_file);

        visibility.reset_qualified_candidate_inspections();
        let candidates = visibility.type_candidates(&consumer, "perf::Exact");
        let inspected = visibility.qualified_candidate_inspections();
        assert_eq!(
            candidates.len(),
            2,
            "qualified type candidates: {candidates:#?}"
        );
        assert!(candidates.contains(&&target_a));
        assert!(candidates.contains(&&target_b));
        assert!(!candidates.contains(&&hidden_same_fqn));
        let raw_type_candidates = visibility.type_name_candidates(&consumer, "perf::Exact");
        assert_eq!(raw_type_candidates.len(), 3);
        assert!(raw_type_candidates.contains(&&same_fqn_function));
        assert_eq!(
            visibility.named_candidates_for_normalized(
                &consumer,
                "perf::Exact",
                TargetKind::FreeFunction
            ),
            vec![&same_fqn_function],
            "target-kind filtering must distinguish a same-FQN free function from types"
        );
        assert_eq!(
            visibility.resolve_type(&consumer, "::Global"),
            Some(global),
            "a leading global qualifier must still resolve the visible global type"
        );
        assert_eq!(
            visibility.resolve_type(&consumer, "perf::Alias"),
            Some(alias.clone()),
            "a namespace-qualified alias must remain a type candidate"
        );
        assert_eq!(
            visibility.alias_target(&alias).map(|unit| unit.fq_name()),
            Some("perf.Exact".to_string()),
            "a qualified namespace alias must resolve its namespace-relative target"
        );
        assert_eq!(
            inspected, 3,
            "qualified lookup should inspect only the two visible type declarations and the same-FQN non-type declaration"
        );
    }

    #[test]
    fn qualified_lookup_uses_the_final_cpp_scope_component_verbatim() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let header = ProjectFile::new(root, "include/types.h");
        let nested = structured_cpp_unit(
            header.clone(),
            CodeUnitType::Class,
            &[
                ("ns", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("Inner", SegmentKind::Nested),
            ],
            None,
        );
        let constructor = structured_cpp_unit(
            header.clone(),
            CodeUnitType::Function,
            &[
                ("ns", SegmentKind::Package),
                ("Widget", SegmentKind::Type),
                ("Widget", SegmentKind::Member),
            ],
            Some("Widget()"),
        );
        let arrow = structured_cpp_unit(
            header.clone(),
            CodeUnitType::Function,
            &[
                ("ns", SegmentKind::Package),
                ("Widget", SegmentKind::Type),
                ("operator->", SegmentKind::Member),
            ],
            Some("Widget* operator->()"),
        );
        let destructor = structured_cpp_unit(
            header,
            CodeUnitType::Function,
            &[
                ("ns", SegmentKind::Package),
                ("Widget", SegmentKind::Type),
                ("~Widget", SegmentKind::Member),
            ],
            Some("~Widget()"),
        );
        let visible_by_file = HashMap::from_iter([(
            consumer.clone(),
            HashSet::from_iter([
                nested.clone(),
                constructor.clone(),
                arrow.clone(),
                destructor.clone(),
            ]),
        )]);
        let cpp = visibility_analyzer(&visible_by_file);
        let visibility = visibility_index(&cpp, visible_by_file);

        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Outer::Inner", TargetKind::Type),
            vec![&nested]
        );
        assert_eq!(
            visibility.resolve_type(&consumer, "ns::Outer::Inner<int>"),
            Some(nested),
            "template arguments must be removed before selecting the final identifier bucket"
        );
        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Widget::Widget", TargetKind::Constructor),
            vec![&constructor]
        );
        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Widget::operator->", TargetKind::Method),
            vec![&arrow],
            "operator-> must not be reduced with terminal_name-style punctuation splitting"
        );
        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Widget::~Widget", TargetKind::Method),
            vec![&destructor]
        );
        assert!(
            visibility
                .candidate_units(&consumer, "::", TargetKind::Type)
                .is_empty(),
            "a degenerate qualified name must fail closed"
        );
    }

    #[test]
    fn owner_candidate_collapse_prefers_one_full_and_rejects_unknown_or_duplicate_full() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let forward = CodeUnit::new(
            ProjectFile::new(root.clone(), "forward.h"),
            CodeUnitType::Class,
            "demo",
            "Widget",
        );
        let full = CodeUnit::new(
            ProjectFile::new(root.clone(), "full.h"),
            CodeUnitType::Class,
            "demo",
            "Widget",
        );
        let duplicate = CodeUnit::new(
            ProjectFile::new(root, "duplicate.h"),
            CodeUnitType::Class,
            "demo",
            "Widget",
        );

        assert!(matches!(
            collapse_owner_candidates(
                [
                    (forward, CppClassDeclarationStrength::Forward),
                    (full.clone(), CppClassDeclarationStrength::Full),
                ]
                .into_iter()
            ),
            DirectOwnerResolution::UniqueFull(owner) if owner == full
        ));
        assert!(matches!(
            collapse_owner_candidates(
                [(full.clone(), CppClassDeclarationStrength::Unknown)].into_iter()
            ),
            DirectOwnerResolution::Ambiguous
        ));
        assert!(matches!(
            collapse_owner_candidates(
                [
                    (full, CppClassDeclarationStrength::Full),
                    (duplicate, CppClassDeclarationStrength::Full),
                ]
                .into_iter()
            ),
            DirectOwnerResolution::Ambiguous
        ));
    }

    #[test]
    fn class_strength_reuses_one_prepared_tree_for_qgis_sized_sibling_set() {
        const SIBLING_COUNT: usize = 113;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "siblings.h");
        let mut source = String::from("#pragma once\nnamespace qgis {\n");
        for index in 0..SIBLING_COUNT {
            if index % 2 == 0 {
                source.push_str(&format!("class Sibling{index};\n"));
            } else {
                source.push_str(&format!("struct Sibling{index} {{ int value; }};\n"));
            }
        }
        source.push_str("}\n");
        file.write(&source).expect("write sibling fixture");

        let project = Arc::new(crate::analyzer::TestProject::new(
            &root,
            crate::analyzer::Language::Cpp,
        ));
        let workspace = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let mut candidates = cpp
            .get_all_declarations()
            .into_iter()
            .filter(|candidate| {
                candidate.is_class()
                    && candidate.package_name() == "qgis"
                    && candidate.short_name().starts_with("Sibling")
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| {
            candidate
                .short_name()
                .trim_start_matches("Sibling")
                .parse::<usize>()
                .expect("numeric sibling suffix")
        });
        assert_eq!(candidates.len(), SIBLING_COUNT, "physical siblings");
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.source() == &file),
            "every candidate must share the same source: {candidates:#?}"
        );

        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        assert!(
            cpp.prepared_syntax(&file).is_some(),
            "prepare shared syntax"
        );
        cpp.reset_cpp_owner_resolution_counts_for_test();
        let strengths = candidates
            .iter()
            .map(|candidate| {
                cpp_class_declaration_strength(
                    &CppDispatch::new(workspace.analyzer()).source(),
                    candidate,
                )
            })
            .collect::<Vec<_>>();
        for (index, strength) in strengths.into_iter().enumerate() {
            let expected = if index % 2 == 0 {
                CppClassDeclarationStrength::Forward
            } else {
                CppClassDeclarationStrength::Full
            };
            assert!(
                strength == expected,
                "Sibling{index} strength changed: expected {}, got {}",
                if expected == CppClassDeclarationStrength::Forward {
                    "forward"
                } else {
                    "full"
                },
                if strength == CppClassDeclarationStrength::Forward {
                    "forward"
                } else if strength == CppClassDeclarationStrength::Full {
                    "full"
                } else {
                    "unknown"
                }
            );
        }
        assert_eq!(
            cpp.cpp_class_strength_parse_count_for_test(),
            0,
            "class strength must not reparse an already-prepared source"
        );
        assert_eq!(
            cpp.prepared_syntax_parse_count_for_test(&file),
            1,
            "all candidates must share the request-scoped prepared tree"
        );
    }

    #[test]
    fn macro_environment_cache_scales_with_event_frontiers_not_call_sites() {
        const REPEATED_CALL_COUNT: usize = 1_000;
        const EVENT_COUNT: usize = 1_000;
        const INCLUDED_EVENT_COUNT: usize = 100;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "many_calls.cpp");
        let header = ProjectFile::new(root.clone(), "macro_bank.h");
        let mut header_source = String::new();
        for index in 0..INCLUDED_EVENT_COUNT {
            header_source.push_str(&format!("#define BANK_{index} {index}\n"));
        }
        header.write(&header_source).expect("write macro bank");
        let mut source = String::from(
            "#include \"macro_bank.h\"\n#define PAIR(value) value, value\nint target(int left, int right);\nvoid use() {\n  int value = 0;\n",
        );
        source.push_str("  target(PAIR(0));\n  target(value, value);\n}\n");
        for index in 0..EVENT_COUNT {
            source.push_str(&format!("#define EVENT_{index} {index}\n"));
        }
        file.write(&source).expect("write macro fixture");

        let project = Arc::new(crate::analyzer::TestProject::new(
            &root,
            crate::analyzer::Language::Cpp,
        ));
        let workspace = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        let roots = [file.clone()].into_iter().collect();
        let visibility = VisibilityIndex::build(
            cpp,
            &CppDispatch::new(workspace.analyzer()).source(),
            &roots,
        );
        let prepared = cpp.prepared_syntax(&file).expect("prepared macro fixture");
        let mut stack = vec![prepared.tree().root_node()];
        let mut calls = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression"
                && node
                    .child_by_field_name("function")
                    .is_some_and(|function| node_text(function, prepared.source()) == "target")
            {
                calls.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }

        calls.sort_by_key(Node::start_byte);
        assert_eq!(calls.len(), 2);
        for _ in 0..REPEATED_CALL_COUNT {
            for call in &calls {
                assert_eq!(
                    visibility.call_arity_evidence(&file, *call, prepared.source()),
                    CallArityEvidence::Exact(2)
                );
            }
        }
        let event_cell = visibility.macro_event_cell(&file);
        let events = event_cell.get().expect("prepared macro events");
        let event_frontiers = events
            .iter()
            .filter(|event| event.byte() > calls[1].end_byte())
            .map(|event| event.byte() + 1)
            .collect::<Vec<_>>();
        assert_eq!(event_frontiers.len(), EVENT_COUNT);
        for frontier in event_frontiers {
            drop(visibility.macro_environment(&file, frontier));
        }
        assert_eq!(
            visibility
                .macro_environment_cursors
                .lock()
                .expect("C++ macro environment cursor cache poisoned")
                .len(),
            1,
            "one worker must retain one bounded forward cursor, not one snapshot per frontier"
        );
        assert_eq!(
            visibility
                .macro_replacement_parse_count
                .load(Ordering::Relaxed),
            1,
            "repeated uses of one macro binding must share one parsed replacement"
        );
        assert_eq!(
            visibility
                .macro_event_application_count
                .load(Ordering::Relaxed),
            INCLUDED_EVENT_COUNT + EVENT_COUNT + 2,
            "the include closure must replay once and sequential frontiers once each"
        );
        assert_eq!(
            visibility
                .macro_environment_copy_count
                .load(Ordering::Relaxed),
            0,
            "sequential calls must mutate the uniquely held cursor environment in place"
        );
    }

    #[test]
    fn concurrent_macro_arity_scans_do_not_share_a_locked_forward_cursor() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "consumer.cpp");
        let exact_header = ProjectFile::new(root.clone(), "exact.h");
        exact_header
            .write("#pragma once\n#define PAIR(value) value, value\n")
            .expect("write exact macro header");
        let conditional_header = ProjectFile::new(root.clone(), "conditional.h");
        conditional_header
            .write("#pragma once\n#define MAYBE_PAIR(value) value, value\n")
            .expect("write conditional macro header");
        file.write(
            "#include \"exact.h\"\n\
             #if ENABLE_CONDITIONAL\n\
             #include \"conditional.h\"\n\
             #endif\n\
             int target(int left, int right);\n\
             void use() {\n\
               target(PAIR(0));\n\
               target(MAYBE_PAIR(0));\n\
             }\n",
        )
        .expect("write macro consumer");

        let project = Arc::new(crate::analyzer::TestProject::new(
            &root,
            crate::analyzer::Language::Cpp,
        ));
        let workspace = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        let roots = HashSet::from_iter([file.clone()]);
        let visibility = VisibilityIndex::build(
            cpp,
            &CppDispatch::new(workspace.analyzer()).source(),
            &roots,
        );

        // Hold this thread's cursor across the worker's complete macro/include replay. A
        // file-global cursor blocks the worker here; a worker-local cursor lets it finish while
        // all immutable syntax, macro-event, and include-protection cells remain shared.
        let main_cursor = visibility.macro_environment_cursor_cell(&file);
        let main_guard = main_cursor
            .lock()
            .expect("main macro environment cursor poisoned");
        let (timely, eventual) = std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let worker_file = &file;
            let worker_visibility = &visibility;
            let worker = scope.spawn(move || {
                let prepared = cpp
                    .prepared_syntax(worker_file)
                    .expect("prepared macro consumer");
                let mut stack = vec![prepared.tree().root_node()];
                let mut calls = Vec::new();
                while let Some(node) = stack.pop() {
                    if node.kind() == "call_expression"
                        && node
                            .child_by_field_name("function")
                            .is_some_and(|function| {
                                node_text(function, prepared.source()) == "target"
                            })
                    {
                        calls.push(node);
                    }
                    for index in (0..node.named_child_count()).rev() {
                        if let Some(child) = node.named_child(index) {
                            stack.push(child);
                        }
                    }
                }
                calls.sort_by_key(Node::start_byte);
                ready_tx
                    .send(())
                    .expect("signal macro worker ready to resolve arity");
                let evidence = calls
                    .into_iter()
                    .map(|call| {
                        worker_visibility.call_arity_evidence(worker_file, call, prepared.source())
                    })
                    .collect::<Vec<_>>();
                tx.send(evidence.clone()).expect("send macro evidence");
                evidence
            });
            ready_rx.recv().expect("macro worker ready signal");
            let timely = rx.recv_timeout(std::time::Duration::from_secs(5));
            drop(main_guard);
            let eventual = worker.join().expect("macro arity worker");
            (timely, eventual)
        });

        let expected = vec![CallArityEvidence::Exact(2), CallArityEvidence::Unknown];
        assert_eq!(
            timely.as_ref().ok(),
            Some(&expected),
            "another target worker must not wait for this thread's forward cursor: {timely:?}"
        );
        assert_eq!(
            eventual, expected,
            "removing cross-worker serialization must preserve exact and fail-closed evidence"
        );
        assert_eq!(
            cpp.prepared_syntax_parse_count_for_test(&file),
            1,
            "concurrent macro replay must retain the request-scoped prepared tree"
        );
        assert_eq!(
            visibility
                .macro_environment_cursors
                .lock()
                .expect("C++ macro environment cursor cache poisoned")
                .len(),
            2,
            "the participating workers must retain independent bounded cursors"
        );
    }

    #[test]
    fn include_guard_cache_requires_one_outer_file_covering_guard() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let guarded = ProjectFile::new(root.clone(), "guarded.h");
        guarded
            .write("#pragma once\n#ifndef GUARDED_H\n#define GUARDED_H\n#define VALUE 1\n#endif\n")
            .expect("write guarded header");
        let macro_guarded = ProjectFile::new(root.clone(), "macro_guarded.h");
        macro_guarded
            .write(
                "#ifndef MACRO_GUARDED_H\n// guard comment\n#define MACRO_GUARDED_H\n#define VALUE 1\n#endif\n",
            )
            .expect("write macro-guarded header");
        let nested = ProjectFile::new(root.clone(), "nested.h");
        nested
            .write(
                "#define BEFORE 1\n#ifndef FEATURE_H\n#define FEATURE_H\n#endif\n#define AFTER 2\n",
            )
            .expect("write nested guard header");
        let pushed = ProjectFile::new(root.clone(), "pushed.h");
        pushed
            .write(
                "#pragma push_macro(\"VALUE\")\n#ifndef PUSHED_H\n#define PUSHED_H\n#define VALUE 3\n#endif\n",
            )
            .expect("write push-macro header");
        let non_once = ProjectFile::new(root.clone(), "non_once.h");
        non_once
            .write("#pragma GCC diagnostic push\n#define VALUE 4\n")
            .expect("write non-once pragma header");

        let project = Arc::new(crate::analyzer::TestProject::new(
            &root,
            crate::analyzer::Language::Cpp,
        ));
        let workspace = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        let roots = [
            guarded.clone(),
            macro_guarded.clone(),
            nested.clone(),
            pushed.clone(),
            non_once.clone(),
        ]
        .into_iter()
        .collect();
        let visibility = VisibilityIndex::build(
            cpp,
            &CppDispatch::new(workspace.analyzer()).source(),
            &roots,
        );

        for _ in 0..100 {
            assert_eq!(
                visibility.macro_include_protection(&guarded),
                MacroIncludeProtection::PragmaOnce
            );
            assert_eq!(
                visibility.macro_include_protection(&macro_guarded),
                MacroIncludeProtection::MacroGuard("MACRO_GUARDED_H".to_string())
            );
            assert_eq!(
                visibility.macro_include_protection(&nested),
                MacroIncludeProtection::None
            );
            assert_eq!(
                visibility.macro_include_protection(&pushed),
                MacroIncludeProtection::None
            );
            assert_eq!(
                visibility.macro_include_protection(&non_once),
                MacroIncludeProtection::None
            );
        }
        assert_eq!(
            visibility
                .macro_include_protection_cells
                .lock()
                .expect("C++ include protection cache poisoned")
                .len(),
            5,
            "include protection classification must be cached once per file"
        );
    }

    #[test]
    fn callable_targets_without_differing_redeclarations_skip_include_activation_work() {
        const TARGET_COUNT: usize = 128;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let header = ProjectFile::new(root.clone(), "api.h");
        let consumer = ProjectFile::new(root.clone(), "consumer.cc");
        let mut declarations = String::from("#pragma once\n");
        for index in 0..TARGET_COUNT {
            declarations.push_str(&format!("int candidate_{index}(int value);\n"));
        }
        header.write(&declarations).expect("write declarations");
        consumer
            .write("#include \"api.h\"\nint consume() { return 0; }\n")
            .expect("write consumer");

        let project = Arc::new(crate::analyzer::TestProject::new(
            &root,
            crate::analyzer::Language::Cpp,
        ));
        let workspace = crate::analyzer::WorkspaceAnalyzer::build(
            project,
            crate::analyzer::AnalyzerConfig::default(),
        );
        let analyzer = workspace.analyzer();
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).expect("C++ analyzer");
        let roots = HashSet::from_iter([consumer.clone()]);
        let visibility = VisibilityIndex::build(cpp, &CppDispatch::new(analyzer).source(), &roots);
        let prepared = cpp.prepared_syntax(&consumer).expect("prepared consumer");
        let targets = cpp
            .get_all_declarations()
            .into_iter()
            .filter(|candidate| {
                candidate.is_function()
                    && candidate.source() == &header
                    && candidate.short_name().starts_with("candidate_")
            })
            .collect::<Vec<_>>();
        assert_eq!(targets.len(), TARGET_COUNT, "scale fixture targets");
        for target in &targets {
            let spec = TargetSpec::from_target(&CppDispatch::new(analyzer).source(), target)
                .expect("target spec");
            assert!(matches!(
                spec.with_visible_callable_arities(
                    &CppDispatch::new(analyzer).source(),
                    cpp,
                    &visibility,
                    &consumer,
                    prepared.as_ref(),
                ),
                Cow::Borrowed(_)
            ));
        }
        assert_eq!(
            visibility.include_activation_build_count_for_test(),
            0,
            "zero-donor targets must not inspect the include graph"
        );
    }

    #[test]
    fn unconditional_include_reachability_is_reused_across_visibility_indexes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let bridge = ProjectFile::new(root.clone(), "bridge.h");
        let donor = ProjectFile::new(root.clone(), "donor.h");
        consumer
            .write("#include \"bridge.h\"\nint consume() { return target(); }\n")
            .expect("write consumer");
        bridge
            .write("#include \"donor.h\"\n")
            .expect("write bridge");
        donor.write("int target();\n").expect("write donor");

        let analyzer = CppAnalyzer::from_project(crate::analyzer::TestProject::new(
            root,
            crate::analyzer::Language::Cpp,
        ));
        let roots = HashSet::from_iter([consumer.clone()]);
        let first =
            VisibilityIndex::build(&analyzer, &CppGraphSource::from_source(&analyzer), &roots);
        let prepared = analyzer
            .prepared_syntax(&consumer)
            .expect("prepared consumer");
        assert!(
            first
                .include_activation_for_source(&analyzer, &consumer, prepared.as_ref(), &donor)
                .is_some(),
            "the direct include must reach the donor through the bridge"
        );

        let second =
            VisibilityIndex::build(&analyzer, &CppGraphSource::from_source(&analyzer), &roots);
        assert!(
            second
                .include_activation_for_source(&analyzer, &consumer, prepared.as_ref(), &donor)
                .is_some(),
            "the shared analyzer cache must preserve the include activation"
        );
        assert_eq!(
            analyzer.unconditional_include_reachability_cache_len_for_test(),
            1,
            "separate visibility indexes must reuse one reachability result"
        );
    }

    #[test]
    fn unconditional_include_reachability_keeps_c_and_cpp_contexts_separate() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let c_consumer = ProjectFile::new(root.clone(), "consumer.c");
        let cpp_consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let bridge = ProjectFile::new(root.clone(), "bridge.h");
        let donor = ProjectFile::new(root.clone(), "donor.h");
        c_consumer
            .write("#include \"bridge.h\"\nint consume_c() { return 0; }\n")
            .expect("write C consumer");
        cpp_consumer
            .write("#include \"bridge.h\"\nint consume_cpp() { return target(); }\n")
            .expect("write C++ consumer");
        bridge
            .write("#ifdef __cplusplus\n#include \"donor.h\"\n#endif\n")
            .expect("write bridge");
        donor.write("int target();\n").expect("write donor");

        let analyzer = CppAnalyzer::from_project(crate::analyzer::TestProject::new(
            root,
            crate::analyzer::Language::Cpp,
        ));
        for (consumer, reaches) in [(c_consumer, false), (cpp_consumer, true)] {
            let roots = HashSet::from_iter([consumer.clone()]);
            let visibility =
                VisibilityIndex::build(&analyzer, &CppGraphSource::from_source(&analyzer), &roots);
            let prepared = analyzer
                .prepared_syntax(&consumer)
                .expect("prepared consumer");
            assert_eq!(
                visibility
                    .include_activation_for_source(&analyzer, &consumer, prepared.as_ref(), &donor)
                    .is_some(),
                reaches,
                "the include closure must respect the reference language"
            );
        }
        assert_eq!(
            analyzer.unconditional_include_reachability_cache_len_for_test(),
            2,
            "the cache must not reuse a C result for a C++ reference"
        );
    }

    #[test]
    fn callable_arity_keeps_compatible_defaults_independent_of_incompatible_donor_order() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let target = CodeUnit::with_signature(
            ProjectFile::new(root, "target.cc"),
            CodeUnitType::Function,
            "demo",
            "route",
            Some("(int, int)".to_string()),
            false,
        );
        for activated_callable_arities in [
            vec![
                ActivatedCallableArity {
                    activation_byte: 1,
                    arity: CallableArity::new(1, 2, false),
                },
                ActivatedCallableArity {
                    activation_byte: 1,
                    arity: CallableArity::new(1, 3, false),
                },
            ],
            vec![
                ActivatedCallableArity {
                    activation_byte: 1,
                    arity: CallableArity::new(1, 3, false),
                },
                ActivatedCallableArity {
                    activation_byte: 1,
                    arity: CallableArity::new(1, 2, false),
                },
            ],
        ] {
            let mut spec = TargetSpec::new(
                target.clone(),
                TargetKind::FreeFunction,
                None,
                "route".to_string(),
                Some(CallableArity::exact(2)),
                Some(vec!["int".to_string(), "int".to_string()]),
            );
            spec.activated_callable_arities = activated_callable_arities;
            let arity = spec.callable_arity_at(1).expect("callable arity");
            assert!(arity.accepts(1), "compatible default must remain active");
            assert!(arity.accepts(2), "full arity must remain active");
            assert!(!arity.accepts(0), "under-arity must remain rejected");
            assert!(!arity.accepts(3), "incompatible donor must remain ignored");
        }
    }

    #[test]
    fn cpp_callable_arity_applies_defaulted_header_to_definition_target() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let definition_file = ProjectFile::new(root.clone(), "api.cpp");
        let header_file = ProjectFile::new(root.clone(), "api.hpp");
        fs::write(
            header_file.abs_path(),
            "#define API\n".to_string()
                + "class XMLNode; class XMLElement;\n"
                + "class API XMLElement : public XMLNode {\n"
                + "public:\n"
                + "  const char* Name() const { return Value(); }\n"
                + "  const char* Attribute(const char* name, const char* value = 0) const;\n"
                + "};\n}\n",
        )
        .expect("write declaration fixture");
        fs::write(
            root.join("api.cpp"),
            "#include \"api.hpp\"\n".to_string()
                + "const char* XMLElement::Attribute(const char* name, const char* value) const {\n"
                + "  return value ? value : name;\n"
                + "}\n",
        )
        .expect("write definition fixture");
        let consumer_file = ProjectFile::new(root.clone(), "consumer.cpp");
        fs::write(
            consumer_file.abs_path(),
            "#include \"api.hpp\"\n".to_string()
                + "const char* consume(const XMLElement* element) {\n"
                + "  return element->Attribute(\"name\");\n"
                + "}\n",
        )
        .expect("write consumer fixture");
        let analyzer = CppAnalyzer::from_project(crate::analyzer::TestProject::new(
            &root,
            crate::analyzer::Language::Cpp,
        ));
        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| {
                unit.is_function()
                    && unit.identifier() == "Attribute"
                    && unit.source() == &definition_file
            })
            .expect("out-of-line definition");
        let header_attribute = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| {
                unit.is_function()
                    && unit.identifier() == "Attribute"
                    && unit.source() == &header_file
            })
            .expect("header declaration");
        assert_eq!(
            header_attribute.fq_name(),
            "XMLElement.Attribute",
            "fragmented export-macro members keep their recovered class owner"
        );
        let roots = HashSet::from_iter([consumer_file.clone()]);
        let visibility =
            VisibilityIndex::build(&analyzer, &CppGraphSource::from_source(&analyzer), &roots);
        let prepared = analyzer
            .prepared_syntax(&consumer_file)
            .expect("prepared consumer");
        let spec = TargetSpec::from_target(&CppGraphSource::from_source(&analyzer), &target)
            .expect("target spec")
            .with_visible_callable_arities(
                &CppGraphSource::from_source(&analyzer),
                &analyzer,
                &visibility,
                &consumer_file,
                prepared.as_ref(),
            )
            .into_owned();
        let arity = spec.callable_arity_at(usize::MAX).expect("callable arity");
        assert!(
            arity.accepts(1),
            "header default must remain callable: {arity:?}"
        );
        assert!(
            arity.accepts(2),
            "full parameter list must remain callable: {arity:?}"
        );
        assert!(
            !arity.accepts(0),
            "required parameter must remain enforced: {arity:?}"
        );
    }
}
