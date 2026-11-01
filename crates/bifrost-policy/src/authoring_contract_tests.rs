use crate::*;

const POLICY: &str = r#"(policy :id "test.example" :name "Example" :message "M" :severity warning :analysis (analysis :type match :selector (rql (call :callee (name "eval")))))"#;

fn workspace_registry(root: &std::path::Path) -> PolicyRegistry {
    PolicyRegistry::new_for_workspace(
        root.to_path_buf(),
        std::sync::Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        )),
        PolicyRegistryLimits::default(),
    )
    .unwrap()
}

#[test]
fn workspace_document_byte_ceiling_admits_exact_limit() {
    let root = tempfile::tempdir().unwrap();
    // MAX_RQLP_SOURCE_BYTES is the public RQLP source ceiling.
    for size in [
        MAX_RQLP_SOURCE_BYTES / 2 + 1,
        MAX_RQLP_SOURCE_BYTES,
        MAX_RQLP_SOURCE_BYTES + 1,
    ] {
        let mut source = format!("{POLICY}\n;");
        source.push_str(&"x".repeat(size - source.len()));
        std::fs::write(root.path().join("policy.rqlp"), source).unwrap();
        let mut registry = workspace_registry(root.path());
        let result = registry.load_policy_path("policy.rqlp");
        assert_eq!(
            result.is_ok(),
            size <= MAX_RQLP_SOURCE_BYTES,
            "{size}: {result:?}"
        );
        assert_eq!(
            registry.policies().len(),
            usize::from(size <= MAX_RQLP_SOURCE_BYTES)
        );
    }
}

#[test]
fn padded_workspace_ranges_index_original_source() {
    let root = tempfile::tempdir().unwrap();
    let source = r#"

    (policy :id "test.relational" :name "Relational" :message "M" :severity warning :analysis (analysis :type assertion
          (bind :name site :query (rql (occurrences :role [member_position])))
          (group :name by-site :by (site.ast_id)
            (aggregate :name winners :op count-distinct :value site.target_id :where ((site.target_id is-null))))
          (assert :group by-site :value winners :cardinality (exactly 1))))"#;
    std::fs::write(root.path().join("policy.rqlp"), source).unwrap();
    let mut registry = workspace_registry(root.path());
    let loaded = registry.load_policy_path("policy.rqlp").unwrap();
    let PolicyAnalysis::Assertion { spec } = &loaded.definition().analysis else {
        panic!("expected assertion");
    };
    let plan = spec.relational.as_ref().unwrap();
    let field = &plan.groups[0].by[0];
    assert_eq!(&source[field.source_range.clone().unwrap()], "site.ast_id");
}

#[test]
fn row_predicate_operator_spelling_is_case_sensitive() {
    for op in ["is-null", "IS-NULL"] {
        let source = format!(
            r#"(policy :id "test.relational" :name "Relational" :message "M" :severity warning :analysis (analysis :type assertion
          (bind :name site :query (rql (occurrences :role [member_position])))
          (group :name by-site :by (site.ast_id)
            (aggregate :name winners :op count-distinct :value site.target_id :where ((site.target_id {op}))))
          (assert :group by-site :value winners :cardinality (exactly 1))))"#
        );
        let result = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp"));
        if op == "is-null" {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(
                result.unwrap_err().diagnostic.code,
                "unknown-row-predicate-operator"
            );
        }
    }
}

fn formatted(source: &str) -> String {
    let options = PolicyFormatOptions::new(80).unwrap();
    let once = format_rqlp_source_with_options(source, &options).unwrap();
    assert_eq!(
        format_rqlp_source_with_options(&once, &options).unwrap(),
        once
    );
    once
}

#[test]
fn selector_paths_require_nonempty_pointer_segments() {
    for path in ["/", "//", "/a/"] {
        assert_eq!(
            PolicySelectorPath::new(path),
            Err(PolicySelectorPathError::EmptySegment)
        );
    }
    for path in ["/a", "/a~1b"] {
        assert_eq!(PolicySelectorPath::new(path).unwrap().as_str(), path);
    }
}

#[test]
fn row_field_identity_distinguishes_fields_and_ignores_locations() {
    use std::hash::{Hash, Hasher};
    let first = RowFieldRef {
        binding: RowBindingName::new("site").unwrap(),
        field: "name".into(),
        source_range: Some(0..9),
    };
    let relocated = RowFieldRef {
        source_range: Some(20..29),
        ..first.clone()
    };
    let other = RowFieldRef {
        field: "kind".into(),
        ..first.clone()
    };
    assert_eq!(first, relocated);
    assert_ne!(first, other);
    let hash = |value: &RowFieldRef| {
        let mut state = std::collections::hash_map::DefaultHasher::new();
        value.hash(&mut state);
        state.finish()
    };
    assert_eq!(hash(&first), hash(&relocated));
}

#[test]
fn packed_vectors_preserve_atom_separation_and_order() {
    let source = "(policy :future [; ordered values
 alpha beta gamma delta])";
    assert_eq!(
        formatted(source),
        "(policy
  :future [
    ; ordered values
    alpha beta gamma delta
  ]
)"
    );
}

#[test]
fn trailing_keyword_buffers_remain_formattable() {
    assert_eq!(
        formatted(
            "(policy ; explanation
 :future)"
        ),
        "(policy
  ; explanation
  :future
)"
    );
}

#[test]
fn formatter_preserves_comment_blocks_and_sibling_indentation() {
    let source = "(policy ; first
 ; second
 :future ; value first
 ; value second
 x ; trailing first
 ; trailing second
)";
    assert_eq!(
        formatted(source),
        "(policy
  ; first
  ; second
  :future
  ; value first
  ; value second
  x
  ; trailing first
  ; trailing second
)"
    );
}

#[test]
fn short_registered_vector_records_stand_on_separate_lines() {
    assert_eq!(
        formatted(
            "(policy :future [; records
 (transition :from a) (transition :from b) (unknown) (unknown)])"
        ),
        "(policy
  :future [
    ; records
    (transition :from a)
    (transition :from b)
    (unknown) (unknown)
  ]
)"
    );
}

#[test]
fn unicode_scalar_width_matches_ascii_width() {
    let ascii = format!("(policy :name \"{}\")", "e".repeat(45));
    let unicode = format!("(policy :name \"{}\")", "\u{e9}".repeat(45));
    assert_eq!(formatted(&ascii), ascii);
    assert_eq!(formatted(&unicode), unicode);
}

#[test]
fn deep_empty_vectors_keep_canonical_spelling() {
    let source = format!("{}[]{}", "(unknown ".repeat(41), ")".repeat(41));
    let output = formatted(&source);
    assert!(output.lines().any(|line| line.trim() == "[]"), "{output}");
    assert!(!output.contains("[ ]"), "{output}");
}

fn directory_source() -> &'static str {
    r#"(policy :id "test.directory" :name "Directory" :message (generated-message :relation can-reach) :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :include-matches [(match-directory :path "entries" :scope recursive :categories (all [selected.source]))])
        :sinks (endpoint-set :entries [(sink :id sink :display-name "Sink" :categories [sink] :selector (rql (call :callee (name "sink"))) :dangerous-operand (argument :index 0) :accepts [untrusted])])) )"#
}

fn write_endpoint(path: &std::path::Path, id: &str) {
    std::fs::write(path, format!(r#"(endpoint :id "{id}" :name "Source" :display-name "Source" :role source :categories [selected.source] :selector (rql (call :callee (name "input"))) :binding return-value :taint (source-semantics :labels [untrusted]))"#)).unwrap();
}

#[test]
fn directory_candidate_limit_rejects_first_excess_candidate_transactionally() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("entries")).unwrap();
    std::fs::write(root.path().join("policy.rqlp"), directory_source()).unwrap();
    write_endpoint(&root.path().join("entries/a.rqlp"), "test.a");
    for (limit, extra) in [(1, false), (1, true)] {
        if extra {
            write_endpoint(&root.path().join("entries/b.rqlp"), "test.b");
        } else if root.path().join("entries/b.rqlp").exists() {
            std::fs::remove_file(root.path().join("entries/b.rqlp")).unwrap();
        }
        let limits = PolicyRegistryLimits::default()
            .with_max_match_directory_candidates(limit)
            .unwrap();
        let mut registry = PolicyRegistry::new_for_workspace(
            root.path().to_path_buf(),
            std::sync::Arc::new(TaintCatalogRegistry::new_without_workspace(
                CatalogRegistryLimits::default(),
            )),
            limits,
        )
        .unwrap();
        let result = registry.load_policy_path("policy.rqlp");
        if limit == 1 && !extra {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(result.is_err());
            assert_eq!(registry.endpoints().len(), 0);
            assert_eq!(registry.policies().len(), 0);
        }
    }
}

#[test]
fn recursive_directory_depth_admits_ceiling_and_refuses_next_level() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("policy.rqlp"), directory_source()).unwrap();
    // The public registry's default max_match_directory_depth is the schema ceiling.
    let maximum = PolicyRegistryLimits::default().max_match_directory_depth();
    let mut directory = root.path().join("entries");
    for _ in 0..maximum {
        directory.push("d");
    }
    std::fs::create_dir_all(&directory).unwrap();
    write_endpoint(&directory.join("a.rqlp"), "test.a");
    let mut registry = workspace_registry(root.path());
    assert!(registry.load_policy_path("policy.rqlp").is_ok());
    std::fs::remove_file(directory.join("a.rqlp")).unwrap();
    directory.push("d");
    std::fs::create_dir(&directory).unwrap();
    write_endpoint(&directory.join("a.rqlp"), "test.a");
    let mut registry = workspace_registry(root.path());
    assert!(
        format!(
            "{:?}",
            registry.load_policy_path("policy.rqlp").unwrap_err()
        )
        .contains("recursion exceeds depth")
    );
    assert_eq!(registry.endpoints().len(), 0);
    assert_eq!(registry.policies().len(), 0);
}
