//! Byte weighing for the Rust usage caches.
//!
//! Every memo in `usage_walks.rs`, plus the analyzer's per-blob fact cache and
//! per-file declaration-fact cache, is bounded by a byte budget rather than by
//! an entry count, so each value shape needs a weigher that reports what it
//! actually holds. The shapes are Rust's, so the weighers live beside them
//! here; the generic builder and the language-neutral weighers are
//! [`brokk_bifrost_core::analyzer::weighted_cache`].

use brokk_bifrost_core::allocation_size::allocation_size;
use brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts;
pub use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashMap;
use std::mem::{size_of, size_of_val};
use std::path::PathBuf;
use std::sync::Arc;

/// Allocated bytes of one owned `String` buffer.
pub(crate) fn string_bytes(value: &String) -> usize {
    allocation_size(value.capacity())
}

/// Allocated bytes of a `Vec`'s own element buffer, excluding what its
/// elements own.
pub(crate) fn vec_buffer_bytes<T>(values: &Vec<T>) -> usize {
    allocation_size(values.capacity() * size_of::<T>())
}

/// Owned allocations below a file handle; the enclosing record counts its inline handle.
fn path_bytes(file: &ProjectFile) -> usize {
    file.allocated_heap_bytes()
}

fn module_heap(module: &crate::usage::ModuleKey) -> usize {
    module.weight_bytes() - size_of::<crate::usage::ModuleKey>()
}
fn domain_heap(domain: &crate::usage::Domain) -> usize {
    domain.weight_bytes() - size_of::<crate::usage::Domain>()
}
fn vector_bytes<T>(values: &Vec<T>, heap: impl Fn(&T) -> usize) -> usize {
    size_of::<Vec<T>>() + vec_buffer_bytes(values) + values.iter().map(heap).sum::<usize>()
}
fn map_bytes<K, V>(values: &HashMap<K, V>, heap: impl Fn((&K, &V)) -> usize) -> usize {
    size_of::<HashMap<K, V>>()
        + brokk_bifrost_core::hash::allocated_table_slot_bytes::<(K, V)>(values.capacity())
        + values.iter().map(heap).sum::<usize>()
}

pub fn weight_declaration_facts(
    _key: &ProjectFile,
    value: &Arc<crate::usage_queries::RustDeclarationFacts>,
) -> u32 {
    let identity = |i: &crate::usage::RustSymbolIdentity| {
        weight_identity(i) - size_of::<crate::usage::RustSymbolIdentity>()
    };
    let pairs = |items: &Vec<(CodeUnit, crate::usage::RustSymbolIdentity)>| {
        vector_bytes(items, |(unit, i)| {
            unit.allocated_bytes() - size_of::<CodeUnit>() + identity(i)
        })
    };
    let bytes = size_of::<crate::usage_queries::RustDeclarationFacts>() + pairs(&value.identities)
        - size_of_val(&value.identities)
        + pairs(&value.value_constructors)
        - size_of_val(&value.value_constructors)
        + vector_bytes(&value.declared_module_domains, |(m, d)| {
            module_heap(m) + domain_heap(d)
        })
        - size_of_val(&value.declared_module_domains)
        + vector_bytes(&value.domains, |(i, domains)| {
            identity(i) + vector_bytes(domains, domain_heap) - size_of_val(domains)
        })
        - size_of_val(&value.domains)
        + vector_bytes(&value.cfg_conditions, |(i, conditions)| {
            identity(i) + vector_bytes(conditions, |c| c.allocated_retained_bytes())
                - size_of_val(conditions)
        })
        - size_of_val(&value.cfg_conditions)
        + vector_bytes(&value.domain_cfg_occurrences, |(i, occurrences)| {
            identity(i)
                + vector_bytes(occurrences, |(d, c)| {
                    domain_heap(d) + c.allocated_retained_bytes()
                })
                - size_of_val(occurrences)
        })
        - size_of_val(&value.domain_cfg_occurrences);
    bytes.min(u32::MAX as usize) as u32
}

pub fn weight_declaration_source_properties<K>(
    _key: &K,
    value: &Arc<crate::graph_support::RustDeclarationSourceProperties>,
) -> u32 {
    let bytes = map_bytes(value, |(unit, properties)| {
        unit.allocated_bytes() - size_of::<CodeUnit>()
            + vector_bytes(properties, |p| p.allocated_retained_bytes())
            - size_of_val(properties)
    });
    bytes.min(u32::MAX as usize) as u32
}

/// Byte weight of one blob's persisted Rust usage facts.
///
/// The identifier-occurrence rows dominate: one entry per distinct identifier
/// in the file, where imports and modules are a handful each. Weighing the
/// strings rather than counting entries keeps the budget honest for a file with
/// a few very long paths.
pub fn weight_rust_usage_facts<K>(_key: &K, value: &Arc<RustUsageFacts>) -> u32 {
    let bytes = size_of::<RustUsageFacts>()
        + vector_bytes(&value.exports, |e| {
            e.exported_name.as_ref().map_or(0, string_bytes)
                + string_bytes(&e.source_path)
                + e.imported_name.as_ref().map_or(0, string_bytes)
        })
        - size_of_val(&value.exports)
        + vector_bytes(&value.import_targets, |i| {
            vector_bytes(&i.module_path, string_bytes) - size_of_val(&i.module_path)
                + i.bound_name.as_ref().map_or(0, string_bytes)
                + i.imported_name.as_ref().map_or(0, string_bytes)
                + string_bytes(&i.owner_module)
                + i.visibility.allocated_retained_bytes()
                + i.cfg_condition.allocated_retained_bytes()
        })
        - size_of_val(&value.import_targets)
        + vector_bytes(&value.modules, |m| {
            string_bytes(&m.module_name) + m.cfg_condition.allocated_retained_bytes()
        })
        - size_of_val(&value.modules)
        + vector_bytes(&value.identifier_occurrences, |o| {
            string_bytes(&o.identifier)
        })
        - size_of_val(&value.identifier_occurrences)
        + value.module_routes.allocated_retained_bytes()
        + vec_buffer_bytes(&value.include_edges)
        + value
            .include_edges
            .iter()
            .map(|e| {
                string_bytes(&e.relative_path)
                    + string_bytes(&e.file_name)
                    + vec_buffer_bytes(&e.host_bindings)
                    + e.host_bindings
                        .iter()
                        .map(|b| {
                            string_bytes(&b.local_name)
                                + string_bytes(&b.module_specifier)
                                + b.imported_name.as_ref().map_or(0, string_bytes)
                        })
                        .sum::<usize>()
            })
            .sum::<usize>();
    bytes.min(u32::MAX as usize) as u32
}

/// Byte weight of a memoized file list (module-backing files, owner crate
/// roots). The paths dominate; the vector header is noise beside them.
#[allow(clippy::ptr_arg)]
pub fn weight_project_file_list<K>(_key: &K, value: &Vec<ProjectFile>) -> u32 {
    vector_bytes(value, path_bytes).min(u32::MAX as usize) as u32
}

/// Byte weight of one memoized module probe.
///
/// The region charges the PathBuf key separately, including for an empty
/// result. This weight counts only the retained file-list allocation.
#[allow(clippy::ptr_arg)]
pub fn weight_module_probe(key: &PathBuf, value: &Vec<ProjectFile>) -> u32 {
    let _ = key; // The budget region owns and charges the key separately.
    vector_bytes(value, path_bytes).min(u32::MAX as usize) as u32
}

/// Byte weight of one module's effective visibility domains. A `None` value is
/// the answer "no file declares this module", which costs only its key.
pub fn weight_module_domains(
    key: &crate::usage::ModuleKey,
    value: &Option<Vec<crate::usage::Domain>>,
) -> u32 {
    let _ = key;
    let bytes = size_of_val(value)
        + value.as_ref().map_or(0, |domains| {
            vector_bytes(domains, domain_heap) - size_of_val(domains)
        });
    bytes.min(u32::MAX as usize) as u32
}

/// Byte weight of one module alias's routes. Each route owns a target path, a
/// target module key, and a domain.
#[allow(clippy::ptr_arg)]
pub fn weight_alias_routes(
    key: &crate::usage::ModuleKey,
    value: &Vec<crate::usage::RustModuleAliasRoute>,
) -> u32 {
    let _ = key;
    vector_bytes(value, |r| {
        path_bytes(&r.target_file) + module_heap(&r.target_module) + domain_heap(&r.domain)
    })
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one file's forward import edges. Each edge owns the importer
/// and target paths, two module keys, its typed binding names, and its domain.
#[allow(clippy::ptr_arg)]
pub fn weight_forward_import_edges(
    _key: &ProjectFile,
    value: &Vec<crate::usage::RustImportEdge>,
) -> u32 {
    weight_import_edges(value).min(u32::MAX as usize) as u32
}

/// Byte weight of the import edges that bind one symbol identity.
#[allow(clippy::ptr_arg)]
pub fn weight_binding_edges(
    key: &crate::usage::RustSymbolIdentity,
    value: &Vec<crate::usage::RustImportEdge>,
) -> u32 {
    let _ = key;
    weight_import_edges(value).min(u32::MAX as usize) as u32
}

fn weight_import_edges(edges: &Vec<crate::usage::RustImportEdge>) -> usize {
    vector_bytes(edges, |edge| weight_import_edge(edge) - size_of_val(edge))
}

fn weight_import_edge(edge: &crate::usage::RustImportEdge) -> usize {
    size_of_val(edge)
        + path_bytes(&edge.importer)
        + path_bytes(&edge.target_file)
        + module_heap(&edge.importer_module)
        + module_heap(&edge.target_module)
        + vector_bytes(&edge.source_path, string_bytes)
        - size_of_val(&edge.source_path)
        + match &edge.kind {
            crate::usage::RustImportEdgeKind::Named {
                imported_name,
                local_name,
            } => string_bytes(imported_name) + string_bytes(local_name),
            crate::usage::RustImportEdgeKind::Unnamed { imported_name } => {
                string_bytes(imported_name)
            }
            crate::usage::RustImportEdgeKind::Namespace { local_name } => string_bytes(local_name),
            crate::usage::RustImportEdgeKind::Glob => 0,
            crate::usage::RustImportEdgeKind::Qualified(path) => {
                vector_bytes(path, string_bytes) - size_of_val(path)
            }
        }
        + domain_heap(&edge.domain)
        + edge.cfg_condition.allocated_retained_bytes()
}

fn weight_identity(identity: &crate::usage::RustSymbolIdentity) -> usize {
    size_of_val(identity)
        + string_bytes(&identity.name)
        + module_heap(&identity.module)
        + path_bytes(&identity.file)
}

/// Byte weight of what one module binds.
#[allow(clippy::ptr_arg)]
pub fn weight_module_bindings(
    key: &(ProjectFile, crate::usage::ModuleKey),
    value: &Vec<crate::usage_walks::RustModuleBinding>,
) -> u32 {
    let _ = key;
    vector_bytes(value, |b| {
        string_bytes(&b.name) + weight_identity(&b.origin) - size_of_val(&b.origin)
            + domain_heap(&b.domain)
            + vec_buffer_bytes(&b.route_files)
            + b.route_files.iter().map(path_bytes).sum::<usize>()
    })
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one file's origin routes, bucketed by first path segment.
pub fn weight_origin_routes(
    _key: &ProjectFile,
    value: &HashMap<String, Vec<crate::usage::RustOriginRoute>>,
) -> u32 {
    map_bytes(value, |(segment, routes)| {
        string_bytes(segment)
            + vector_bytes(routes, |r| {
                module_heap(&r.importer_module) + vector_bytes(&r.path, string_bytes)
                    - size_of_val(&r.path)
                    + weight_identity(&r.origin)
                    - size_of_val(&r.origin)
                    + domain_heap(&r.domain)
                    + vec_buffer_bytes(&r.route_files)
                    + r.route_files.iter().map(path_bytes).sum::<usize>()
                    + r.cfg_condition.allocated_retained_bytes()
            })
            - size_of_val(routes)
    })
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one file's macro scope edges.
#[allow(clippy::ptr_arg)]
pub fn weight_macro_scope_edges(
    _key: &ProjectFile,
    value: &Vec<crate::usage::RustMacroScopeEdge>,
) -> u32 {
    vector_bytes(value, |e| {
        module_heap(&e.parent.module)
            + path_bytes(&e.parent.file)
            + module_heap(&e.child.module)
            + path_bytes(&e.child.file)
    })
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one macro's visible ranges, per scope.
pub fn weight_macro_visible_ranges(
    key: &CodeUnit,
    value: &crate::usage::RustMacroScopeRanges,
) -> u32 {
    let _ = key;
    map_bytes(value, |(scope, ranges)| {
        path_bytes(&scope.file) + module_heap(&scope.module) + vec_buffer_bytes(ranges)
    })
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one file's composed include-expansion routes. The host
/// bindings dominate: a deeply nested include accumulates one per binding
/// visible at each splice it passed through.
#[allow(clippy::ptr_arg)]
pub fn weight_include_routes(
    _key: &ProjectFile,
    value: &Vec<crate::usage_includes::RustIncludeRoute>,
) -> u32 {
    vector_bytes(value, |r| {
        path_bytes(&r.root_file)
            + string_bytes(&r.crate_package)
            + string_bytes(&r.module_package)
            + vector_bytes(&r.host_bindings, |b| {
                string_bytes(&b.local_name)
                    + string_bytes(&b.module_specifier)
                    + b.imported_name.as_ref().map_or(0, string_bytes)
                    + string_bytes(&b.module_package)
            })
            - size_of_val(&r.host_bindings)
    })
    .min(u32::MAX as usize) as u32
}

/// Byte weight of one module short name's declaring files, grouped by the
/// module package each declaration names.
///
/// The key is one identifier and the value is the whole workspace answer for
/// it, so the group strings and their file paths carry the cost.
// The key type is
// `String`.
#[allow(clippy::ptr_arg)]
pub fn weight_module_declarations(key: &String, value: &HashMap<String, Vec<ProjectFile>>) -> u32 {
    let _ = key;
    map_bytes(value, |(package, files)| {
        string_bytes(package)
            + vec_buffer_bytes(files)
            + files.iter().map(path_bytes).sum::<usize>()
    })
    .min(u32::MAX as usize) as u32
}

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
#[doc(hidden)]
pub fn check_allocated_fact_regions() {
    use crate::usage::{Domain, ModuleKey, RustSymbolIdentity, RustSymbolNamespace};
    use crate::usage_queries::RustDeclarationFacts;
    use brokk_bifrost_core::allocation_size::counting::check_region;
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
    use brokk_bifrost_core::retention_budget::{RetainedBytes, RetentionBudget};
    struct Sample<T> {
        _value: Arc<T>,
        bytes: usize,
    }
    impl<T> RetainedBytes for Sample<T> {
        fn retained_bytes(&self) -> usize {
            self.bytes
        }
    }
    let mut source = String::from("pub mod nested { pub fn item() {} }\n");
    for i in 0..24 {
        source.push_str(&format!(
            "#[cfg(feature = \"feature_{i}\")] pub use crate::nested::item as exported_{i};\n"
        ));
    }
    source.push_str("include!(\"included.rs\");\n");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&source, None).unwrap();
    let file = ProjectFile::new(std::env::temp_dir(), "12817-facts/src/lib.rs");
    let parsed = crate::declarations::parse_rust_file_with(
        &crate::crate_naming::RustCrateNamingCaches::new(&RetentionBudget::retain_nothing()),
        &file,
        &source,
        &tree,
    );
    let template = parsed.rust_usage_facts.clone();
    check_region("rust.usage_facts", || {
        let value = Arc::new(template.clone());
        let bytes = weight_rust_usage_facts(&file, &value) as usize;
        Sample {
            _value: value,
            bytes,
        }
    });
    // Real mounted declaration names from the same parser fixture populate the
    // actual DTO, including each owning vector and nested domain/cfg buffer.
    let units = parsed.declarations().iter().cloned().collect::<Vec<_>>();
    assert!(!units.is_empty());
    check_region("rust.declaration_facts", || {
        let module = ModuleKey {
            crate_root: "fixture".into(),
            components: vec!["nested".into()],
        };
        let identities = units
            .iter()
            .map(|unit| {
                let declaration = CodeUnit::from_fq(
                    ProjectFile::new(file.root().to_path_buf(), file.rel_path().to_path_buf()),
                    unit.kind(),
                    unit.fq().clone(),
                    unit.package_segment_count(),
                    unit.signature().map(str::to_owned),
                    false,
                );
                let identity = RustSymbolIdentity {
                    file: declaration.source().clone(),
                    module: module.clone(),
                    name: declaration.identifier().to_owned(),
                    namespace: RustSymbolNamespace::Value,
                };
                (declaration, identity)
            })
            .collect::<Vec<_>>();
        let cfg = RustCfgCondition::Atom("selected_feature".into());
        let value = Arc::new(RustDeclarationFacts {
            value_constructors: identities.clone(),
            declared_module_domains: vec![(module.clone(), Domain::Module(module.clone()))],
            domains: identities
                .iter()
                .map(|(_, i)| {
                    (
                        i.clone(),
                        vec![Domain::Public, Domain::Module(module.clone())],
                    )
                })
                .collect(),
            cfg_conditions: identities
                .iter()
                .map(|(_, i)| (i.clone(), vec![cfg.clone()]))
                .collect(),
            domain_cfg_occurrences: identities
                .iter()
                .map(|(_, i)| {
                    (
                        i.clone(),
                        vec![(Domain::Module(module.clone()), cfg.clone())],
                    )
                })
                .collect(),
            identities,
            ..RustDeclarationFacts::default()
        });
        let bytes = weight_declaration_facts(&file, &value) as usize;
        Sample {
            _value: value,
            bytes,
        }
    });
}
