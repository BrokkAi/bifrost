//! Reconstruction of per-violation rerun configurations from a ledger record.
//!
//! `--rerun LINE` re-executes the failing slice of a recorded run instead of
//! replaying verbatim probe arguments: probes are re-derived from the
//! deterministic sample (same seed, same walk) narrowed to each violation's
//! reproduction scope — the exemplar symbol for symbol-scoped findings, the
//! declaring file for file-scoped ones (the I3a summaries chain). Group
//! checks (I2 spelling groups, batch + singles, follow-ups) regenerate per
//! scope, so a rerun stays minutes-cheap even on large repositories while
//! exercising the same code paths as the original run.

use serde_json::Value;

use crate::mcp_property_fuzzer::FuzzerConfig;

/// Build one `(signature, config)` pair per violation recorded in
/// `record["report"]["violations"]`, optionally narrowed to signatures
/// containing `signature_filter`.
///
/// The rerun config is the recorded base config narrowed to the violation's
/// reproduction scope:
/// - symbol-scoped violations (most of them): `symbol_filter` is set to the
///   violation's exemplar symbol, regenerating just that symbol's probes.
/// - file-scoped violations (`summaries-listed-*`, the I3a chain): their
///   exemplar "symbol" is an element name from the summaries *response*,
///   which usually is not a sampled workspace symbol — a symbol filter would
///   empty the probe set (observed on chisel: `probe_calls=0`, signature
///   MISSING). These rerun via `path_filter` on the violation's file, which
///   regenerates the file's summaries probe and its element follow-ups.
/// - I5 and symbol-less violations keep the base config: I5 negatives derive
///   from the whole service sample, so filtering would empty the probe set.
///
/// I1 violations reproduce through the full deterministic index walk
/// regardless, since both filters only narrow service-layer probes.
pub fn rerun_configs(
    record: &Value,
    signature_filter: Option<&str>,
) -> Result<Vec<(String, FuzzerConfig)>, String> {
    let report = record
        .get("report")
        .ok_or_else(|| "ledger record has no `report` object".to_string())?;
    let config_value = report
        .get("config")
        .cloned()
        .ok_or_else(|| "ledger record has no `report.config`".to_string())?;
    let base: FuzzerConfig = serde_json::from_value(config_value)
        .map_err(|err| format!("failed to decode `report.config`: {err}"))?;
    let violations = report
        .get("violations")
        .and_then(Value::as_array)
        .ok_or_else(|| "ledger record has no `report.violations` array".to_string())?;
    let mut configs = Vec::new();
    for violation in violations {
        let Some(signature) = violation.get("signature").and_then(Value::as_str) else {
            continue;
        };
        if let Some(filter) = signature_filter
            && !signature.contains(filter)
        {
            continue;
        }
        let invariant = violation
            .get("invariant")
            .and_then(Value::as_str)
            .unwrap_or("");
        let symbol = violation
            .get("symbol")
            .and_then(Value::as_str)
            .unwrap_or("");
        let path = violation.get("path").and_then(Value::as_str).unwrap_or("");
        let mut config = base.clone();
        if signature.contains("summaries-listed") {
            // File-scoped (I3a): reproduce through the file's summaries
            // probe, not the response-side element name.
            config.symbol_filter = None;
            if !path.is_empty() {
                config.path_filter = Some(path.to_string());
            }
        } else if invariant != "I5" && !symbol.is_empty() {
            config.symbol_filter = Some(symbol.to_string());
        }
        configs.push((signature.to_string(), config));
    }
    if configs.is_empty() {
        return Err(match signature_filter {
            Some(filter) => format!("no violations in the record match --signature `{filter}`"),
            None => "the record lists no violations to rerun".to_string(),
        });
    }
    Ok(configs)
}
