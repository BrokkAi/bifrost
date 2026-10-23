pub mod analyzer {
    pub mod python;
    pub use python::packaging as python_packaging;
    pub use python::runtime_artifact as python_runtime_artifact;
    pub use python::{
        PythonAnalyzer, PythonImportBinding,
        external::{
            PythonArtifactPackProducer, PythonDependencyPackAdapter,
            resolve_python_semantic_pack_dependencies,
        },
        parse_python_import_bindings, parse_python_import_infos,
        python_builtin_exception_is_subclass, python_builtin_exception_name,
    };

    pub mod usages {
        pub mod get_definition {
            pub mod python;
        }
        pub mod get_type {
            pub(crate) use python::resolve_python_type_bounded;
            pub mod python;
        }
        pub mod python_graph;
    }
}

pub use analyzer::python::*;

pub use analyzer::usages::python_graph::PythonExportUsageGraphStrategy;
pub use analyzer::{
    PythonArtifactPackProducer, PythonDependencyPackAdapter, python_packaging,
    python_runtime_artifact, resolve_python_semantic_pack_dependencies,
};

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    use std::sync::OnceLock;
    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::partial_for_tests(vec![&PythonSupport as &dyn LanguageSupport])
    })
}
#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<brokk_bifrost_analysis::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}
