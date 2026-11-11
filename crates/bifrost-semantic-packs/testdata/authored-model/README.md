# Authored semantic-model fixture

`unittest-assertions-2026.9.7.json`, its pinned spec and `notices/` are exact
copies of the CPython `unittest` assertion pack this repository shipped under
`semantic-packs/python/` until #4438 (last carried at commit `96c34229bc`). The
pack is now authored and released in `BrokkAi/bifrost-packs`.

The release-bundle tests in `src/release_bundle.rs` read these bytes as a real
authored-model input: the spec pins the artifact's SHA-256, so the files must
stay byte-identical to each other. Do not update them to follow the pack
repository; they exercise the engine's producer and measurement contracts, not
the pack's content. The directory is excluded from the published crate.
