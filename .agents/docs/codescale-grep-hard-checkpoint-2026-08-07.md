# CodeScaleBench grep-hard checkpoint (2026-08-07)

## Status

Arms 01 (bare) and 02 (symbols) are complete and scored for the 14-task paired manifest
`.agents/docs/codescale-grep-hard-luna-max-r3-shovel14.tasks`. Arm 03 (symbols plus NLP) has not started.

This is the first valid Bifrost arm. The validity gate passed: 0 MCP-start errors, 14 of 14
`mcp server ready` records, 14 of 14 tasks with at least one successful Bifrost call.

## The r11 stall

The symbols arm stopped on 2026-08-06 because the driver died of SIGHUP when the SSH session
that launched it disconnected at 12:32:02. Five tasks had completed; nine were orphaned.
The orphaned in-container agents completed normally (podman exec survives client death); their
outputs were salvaged for diagnosis only (`symbols-r11-orphan-salvage-v1/`) and were not scored.
One orphan (`ccx-dep-trace-264`, Firefox) ran 7 h 20 min and OOM-killed Bifrost five times
against the 8 GiB container limit. There was no harness or Bifrost defect in the stall itself.
Full diagnosis: `symbols-r11-stall-diagnosis-v1.md` in the campaign directory.

The nine missing tasks reran cleanly in `symbols-r12-final/` (runtime-r25 unchanged, sha256
verified against r11; driver setsid-detached, PID file kept). All nine completed in 1,897 s
with zero OOM kills.

## Paired result (10 comparable tasks)

- Mean composite: bare 0.6019, symbols 0.6021 (delta +0.0003). Median: 0.5732 vs 0.5821.
- Solves: 0 in both arms.
- File F1 is identical in all 10 tasks; only symbol recall moved (one task up, two down).
- Symbols used 5.88M tokens vs 6.91M bare at equal cost, with 18 percent more wall time.
- 4 of 14 symbols tasks are unscored: 2 timeouts (both Firefox, both burned by 1,200 s
  get_symbol_sources calls that exhausted the request budget) and 2 invalid outputs.
- semantic_search was not available in this arm; utility tokens were 0 in both arms.

## Latency

148 of 381 Bifrost calls (39 percent) exceeded the 5 s product limit; the median slow call was
27.3 s. Worst: get_symbol_sources 1200.3 s and 1200.1 s (Firefox, budget-terminated),
591.9 s (Kubernetes); scan_usages_by_reference 591.9 s (Kubernetes) and 380.7 s (Envoy).
Caveat: nine large repositories ran concurrently against one shared SQLite cache, so these
numbers include contention. Evidence recorded on issue #1688 (get_symbol_sources) and new
issue #1748 (scan_usages_by_reference). Isolated warm reruns of the worst calls are the first
step before any fix.

## Artifacts

All in `/mnt/containers/code_isnt_memory/codescale-grep-hard-cleanup-20260805/`:
`paired14-bare-scores-v1.json`, `paired14-symbols-vs-bare-v1.json` and `.md`,
`symbols-r11-stall-diagnosis-v1.md`, `symbols-r12-final/`, `symbols-r11-orphan-salvage-v1/`,
`build-paired14-report-v1.py`.

## Next actions

1. Decide on arm 03 (symbols plus NLP): same manifest and runtime-r25, NLP enabled. It needs a
   GPU assignment for the embedding sidecar.
2. Run isolated warm reruns of the worst get_symbol_sources and scan_usages_by_reference calls
   to split contention from single-request cost (#1688, #1748).
3. Decide whether the two Firefox timeout tasks get a rerun after latency fixes, or stand as
   recorded. Under the never-mix-runtimes rule, a rerun with a fixed Bifrost would be a new
   campaign, not a patch to this arm.
4. The too-broad scope guards landed on bifrost-nlp-ft after runtime-r25 was built. They are
   not in this campaign and must not enter it mid-arm. A future campaign can measure them.
