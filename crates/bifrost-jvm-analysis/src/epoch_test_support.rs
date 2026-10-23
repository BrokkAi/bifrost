//! JVM predecessor-epoch fixture helpers relocated without changing salts.
pub use brokk_bifrost_analysis::analyzer::store::epoch::*;

pub fn kotlin_epoch_before_type_alias_type_identity() -> String {
    compute_epoch_before_bump::<Kotlin>(
        &brokk_bifrost_jvm::kotlin::language::LANGUAGE.into(),
        "kotlin-type-alias-type-identity-2026-09",
    )
}

pub fn kotlin_epoch_before_call_navigation_receiver_facts() -> String {
    let prior = salt_before_bump(
        Kotlin::SALT,
        "kotlin-call-navigation-receiver-facts-2026-10",
    );
    compute_epoch::<Kotlin>(&brokk_bifrost_jvm::kotlin::language::LANGUAGE.into(), prior)
}

pub fn scala_epoch_before_type_alias_type_identity() -> String {
    compute_epoch_before_bump::<Scala>(
        &brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
        "scala-type-alias-type-identity-2026-09",
    )
}

pub fn scala_epoch_before_native_root_route_facts() -> String {
    let prior = salt_before_bump(Scala::SALT, "scala-native-root-route-facts-2026-10");
    compute_epoch::<Scala>(&brokk_bifrost_jvm::scala::language::LANGUAGE.into(), prior)
}

pub fn scala_epoch_before_top_level_extension_declarations() -> String {
    let prior = salt_before_bump(Scala::SALT, "top-level-extension-declarations-2026-08");
    compute_epoch::<Scala>(&brokk_bifrost_jvm::scala::language::LANGUAGE.into(), prior)
}

pub fn scala_epoch_before_scalachess_fqn_recovery() -> String {
    compute_epoch::<Scala>(
        &brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07",
    )
}

pub fn scala_epoch_before_tree_sitter_scala_0_26_2() -> String {
    compute_epoch::<Scala>(
        &brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
        "synthetic-file-scope-code-units-2026-07;scala-raw-supertypes-and-traits-2026-07;ast-test-detection-2026-07;curried-constructor-and-parameter-field-semantics-2026-07;recovered-indentation-type-ownership-2026-07;parser-backed-export-facts-2026-07;parameterized-enum-case-declarations-2026-07;supertype-package-prefix-context-2026-07;supertype-lexical-scope-context-2026-07;tree-sitter-scala-bifrost-patches-1016-1068-1073-2026-07;comment-immune-tuple-pattern-binding-names-2026-07;fq-interned-segments-2026-07;scalachess-fqn-recovery-2026-07;jvm-query-assets-in-brokk-bifrost-jvm-2026-08",
    )
}
