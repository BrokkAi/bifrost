use brokk_analyzer::usages::{LocalInferenceConfig, LocalInferenceEngine, SymbolResolution};

fn precise_targets(resolution: SymbolResolution<&'static str>) -> Vec<&'static str> {
    let mut values: Vec<_> = resolution
        .as_precise()
        .expect("expected precise resolution")
        .iter()
        .copied()
        .collect();
    values.sort_unstable();
    values
}

#[test]
fn alias_propagation_preserves_seeded_targets() {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    engine.seed_symbol("service", "Service");
    engine.alias_symbol("alias", "service");

    assert_eq!(
        vec!["Service"],
        precise_targets(engine.resolve_symbol("alias"))
    );
}

#[test]
fn exiting_scope_restores_outer_binding() {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    engine.seed_symbol("service", "OuterService");

    engine.enter_scope();
    engine.seed_symbol("service", "InnerService");
    assert_eq!(
        vec!["InnerService"],
        precise_targets(engine.resolve_symbol("service"))
    );

    engine.exit_scope();
    assert_eq!(
        vec!["OuterService"],
        precise_targets(engine.resolve_symbol("service"))
    );
}

#[test]
fn shadow_without_binding_blocks_outer_binding_within_scope() {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    engine.seed_symbol("service", "Service");

    engine.enter_scope();
    engine.declare_shadow("service");
    assert!(engine.resolve_symbol("service").is_unknown());

    engine.exit_scope();
    assert_eq!(
        vec!["Service"],
        precise_targets(engine.resolve_symbol("service"))
    );
}

#[test]
fn ambiguity_cap_degrades_resolution() {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig {
        max_targets_per_symbol: 2,
    });
    engine.seed_symbol_many("service", ["A", "B", "C"]);

    assert!(engine.resolve_symbol("service").is_ambiguous());
}

#[test]
fn snapshot_reports_matching_symbols_and_shadows() {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    engine.seed_symbol("service", "Service");
    engine.seed_symbol("helper", "Helper");
    engine.enter_scope();
    engine.alias_symbol("alias", "service");
    engine.declare_shadow("helper");

    let snapshot = engine.snapshot();
    assert!(snapshot.is_shadowed("helper"));

    let mut symbols: Vec<_> = snapshot
        .matching_symbols(|target| *target == "Service")
        .into_iter()
        .collect();
    symbols.sort();
    assert_eq!(vec!["alias".to_string(), "service".to_string()], symbols);
}
