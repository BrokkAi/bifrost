use super::RubyAdapter;
use crate::analyzer::{ProjectFile, TreeSitterAnalyzer};

impl TreeSitterAnalyzer<RubyAdapter> {
    pub(crate) fn canonical_ruby_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<brokk_bifrost_core::analyzer::ruby_facts::RubyFileSourceInfo> {
        let reader = self.canonical_source_read(file, "ruby")?;
        if let Some(state) = reader.retained_primary() {
            let source = state
                .source_facts
                .as_ref()
                .expect("retained canonical source facts");
            let ruby = source.ruby.as_ref()?;
            return Some(
                brokk_bifrost_core::analyzer::ruby_facts::RubyFileSourceInfo {
                    source_bytes: source.source_bytes,
                    has_parse_errors: ruby.has_parse_errors,
                    runtime_boundary: ruby.runtime_boundary.map(|(_, kind)| kind),
                    loads: ruby
                        .loads
                        .iter()
                        .map(
                            |load| brokk_bifrost_core::analyzer::ruby_facts::RubyLoadInfo {
                                import: source.imports[load.import.index()]
                                    .import_info(&source.occurrences),
                                kind: load.kind,
                                has_receiver: load.has_receiver,
                                autoload_constant: load.autoload_constant.clone(),
                                generic: source.generic_imports.contains(&load.import),
                            },
                        )
                        .collect(),
                },
            );
        }
        reader.read(
            "reading canonical Ruby load facts",
            |store, oid, generation, _adapter| store.ruby_source_facts(oid, generation),
        )
    }
}
