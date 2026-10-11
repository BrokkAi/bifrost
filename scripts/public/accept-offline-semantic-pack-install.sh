#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 8 ]]; then
  echo "usage: $0 BIFROST INSTALLER BUNDLE POLICY_ROOT CACHE OUTCOME_RECEIPT JAVA_HOME SCRATCH_ROOT" >&2
  exit 2
fi

bifrost=$(realpath "$1")
installer=$(realpath "$2")
bundle=$(realpath "$3")
policy_root=$(realpath "$4")
pack_cache=$(realpath "$5")
outcome_receipt=$(realpath "$6")
java_home=$(realpath "$7")
scratch_parent=$(realpath "$(dirname "$8")")
scratch="$scratch_parent/$(basename "$8")"

for executable in "$bifrost" "$installer"; do
  [[ -x "$executable" ]] || { echo "not executable: $executable" >&2; exit 2; }
done
for directory in "$bundle" "$policy_root" "$pack_cache"; do
  [[ -d "$directory" ]] || { echo "not a directory: $directory" >&2; exit 2; }
done
[[ -s "$outcome_receipt" ]] || { echo "missing acquisition outcome: $outcome_receipt" >&2; exit 2; }
[[ -x "$java_home/bin/java" && -d "$java_home/jmods" ]] || {
  echo "JAVA_HOME is not a complete JDK: $java_home" >&2
  exit 2
}

# The acquisition job owns selection. Consume its exact outcome and receipt;
# this acceptance must never select another release or refresh the cache.
live_profile=$("$bifrost" pack-engine-profile)
selection_id=$(LIVE_PROFILE_JSON="$live_profile" node - "$outcome_receipt" "$bifrost" "$bundle" "$policy_root" "$pack_cache" <<'NODE'
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { isDeepStrictEqual } = require("node:util");

const [outcomePath, executablePath, bundleRoot, policyRoot, cacheRoot] = process.argv.slice(2);
const profile = JSON.parse(process.env.LIVE_PROFILE_JSON);
const outcome = JSON.parse(fs.readFileSync(outcomePath, "utf8"));

const fail = (message) => {
  throw new Error(message);
};
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is not an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!isDeepStrictEqual(actual, expected)) {
    fail(`${label} keys differ: expected ${expected.join(",")}, got ${actual.join(",")}`);
  }
};
const nonempty = (value, label) => {
  if (typeof value !== "string" || value.length === 0) fail(`${label} is missing`);
};
const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const real = (file) => fs.realpathSync(file);
const requireDirectory = (directory, label) => {
  if (!fs.statSync(directory).isDirectory()) fail(`${label} is not a directory: ${directory}`);
};
const requireSamePath = (actual, expected, label) => {
  if (real(actual) !== real(expected)) fail(`${label} disagrees: ${actual} vs ${expected}`);
};

exactKeys(outcome, [
  "outcome_schema_version",
  "status",
  "engine",
  "request",
  "failure",
  "rejections",
  "inventory",
  "selection",
  "created_at",
], "acquisition outcome");
if (outcome.outcome_schema_version !== 1 || outcome.status !== "selected") {
  fail("acquisition outcome is not a selected schema-1 result");
}
if (outcome.failure !== null || !Array.isArray(outcome.rejections) || !outcome.selection) {
  fail("selected acquisition outcome has an invalid failure or selection");
}
exactKeys(outcome.engine, ["version", "build_identity", "executable_sha256"], "outcome engine");
exactKeys(profile, [
  "build_identity",
  "capabilities",
  "capability_contract_version",
  "engine_version",
  "model_set_sha256",
  "schemas",
], "live pack-engine-profile");
nonempty(profile.engine_version, "live engine version");
nonempty(profile.build_identity, "live engine build identity");
if (outcome.engine.version !== profile.engine_version || outcome.engine.build_identity !== profile.build_identity) {
  fail("acquisition outcome engine identity disagrees with live pack-engine-profile");
}
const executableDigest = sha256(executablePath);
if (outcome.engine.executable_sha256 !== executableDigest) {
  fail(`acquisition outcome executable digest differs: ${outcome.engine.executable_sha256} vs ${executableDigest}`);
}

const selection = outcome.selection;
exactKeys(selection, [
  "selection_id",
  "selection_reason",
  "cache_reused",
  "receipt_path",
  "policy_pack_root",
  "semantic_bundle_root",
  "receipt",
], "outcome selection");
if (!/^[a-f0-9]{64}$/u.test(selection.selection_id)) fail("selection id is not a lowercase SHA-256 identity");
nonempty(selection.receipt_path, "selection receipt path");
nonempty(selection.policy_pack_root, "selected policy root");
nonempty(selection.semantic_bundle_root, "selected semantic bundle root");
const selectionReceiptPath = real(selection.receipt_path);
const selectionRoot = path.dirname(selectionReceiptPath);
if (path.basename(selectionRoot) !== selection.selection_id) fail("selection receipt directory does not match selection_id");
const receipt = JSON.parse(fs.readFileSync(selectionReceiptPath, "utf8"));
exactKeys(receipt, [
  "receipt_schema_version",
  "status",
  "selection_id",
  "selection_reason",
  "request",
  "engine",
  "source",
  "releases",
  "rejections",
  "extracted_files",
  "artifacts",
  "replay",
  "created_at",
], "selection receipt");
if (receipt.receipt_schema_version !== 3 || !["qualified", "compatible"].includes(receipt.status)) {
  fail("selected receipt is not a schema-3 compatible selection");
}
if (receipt.selection_id !== selection.selection_id || receipt.selection_reason !== selection.selection_reason) {
  fail("selection_id or selection_reason disagrees with the selected receipt");
}
if (!isDeepStrictEqual(selection.receipt, receipt)) fail("outcome embedded receipt differs from the selected receipt file");
exactKeys(receipt.engine, ["version", "build_identity", "profile"], "selection receipt engine");
if (receipt.engine.version !== profile.engine_version || receipt.engine.build_identity !== profile.build_identity ||
    !isDeepStrictEqual(receipt.engine.profile, profile)) {
  fail("selected receipt profile disagrees with live pack-engine-profile");
}

requireDirectory(bundleRoot, "selected semantic bundle root");
requireDirectory(policyRoot, "selected policy root");
requireDirectory(cacheRoot, "selected semantic cache root");
requireSamePath(selection.policy_pack_root, policyRoot, "policy root");
requireSamePath(selection.semantic_bundle_root, bundleRoot, "semantic bundle root");
const expectedCacheRoot = path.join(path.dirname(path.dirname(path.dirname(selectionReceiptPath))), "semantic-pack-catalog-v1");
requireSamePath(cacheRoot, expectedCacheRoot, "semantic cache root");
requireSamePath(path.join(selectionRoot, "root", "rules"), policyRoot, "receipt policy root");

if (!Array.isArray(receipt.releases)) fail("selected receipt releases are missing");
const rootRelease = receipt.releases.find((release) => release.role === "root");
if (!rootRelease || rootRelease.pack_id !== "bifrost.public.rules") fail("selected receipt root is not bifrost.public.rules");
const nativeDependency = receipt.releases.find((release) =>
  release.role === "dependency" && Array.isArray(release.artifacts) && release.artifacts.some((artifact) => artifact.role === "native"),
);
if (!nativeDependency) fail("selected receipt has no native semantic-pack dependency");
requireSamePath(
  path.join(selectionRoot, `dependency-${nativeDependency.pack_id}`, "bifrost-semantic-packs"),
  bundleRoot,
  "receipt semantic bundle root",
);
if (!fs.existsSync(path.join(bundleRoot, "index.json"))) fail("selected semantic bundle has no index.json");

// The selected policy source is the authoritative semantic-hash source. Its
// bytes must be covered by both producer receipt records before it is used.
const manifestRelativePath = "rules/bifrost.security/manifest.json";
const sourceManifest = path.join(policyRoot, "bifrost.security", "manifest.json");
const manifestContent = rootRelease.contents?.find((content) => content.path === manifestRelativePath);
const extractedManifest = receipt.extracted_files?.root?.find((file) => file.path === manifestRelativePath);
if (!manifestContent || !extractedManifest) fail("selected receipt does not cover bifrost.security/manifest.json");
const sourceManifestDigest = sha256(sourceManifest);
if (sourceManifestDigest !== manifestContent.sha256 || sourceManifestDigest !== extractedManifest.sha256) {
  fail("selected policy manifest digest disagrees with the producer receipt");
}
if (fs.statSync(sourceManifest).size !== extractedManifest.size_bytes) {
  fail("selected policy manifest size disagrees with the producer receipt");
}

process.stdout.write(`${selection.selection_id}\n`);
NODE
)

selection_receipt=$(node -e 'const fs = require("node:fs"); const outcome = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(outcome.selection.receipt_path)' "$outcome_receipt")
selection_receipt=$(realpath "$selection_receipt")
policy_manifest="$policy_root/bifrost.security/manifest.json"

rm -rf "$scratch"
mkdir -p "$scratch/workspace/src/main/java/fixture" "$scratch/empty-home"
workspace="$scratch/workspace"
catalog="$workspace/.bifrost/semantic-pack-catalog"
mkdir -p "$workspace/.bifrost"
cat > "$workspace/.bifrost/packs.json" <<'JSON'
{
  "schema_version": 1,
  "catalog": ".bifrost/semantic-pack-catalog",
  "ecosystems": ["jvm"]
}
JSON
cat > "$workspace/src/main/java/fixture/App.java" <<'JAVA'
package fixture;

final class SameNameSystem {
    static String getenv(String name) { return name; }
}

final class SameNameRuntime {
    void exec(String command) {}
}

public final class App {
    void positive(Runtime runtime) throws Exception {
        String command = System.getenv("COMMAND");
        runtime.exec(command);
    }

    void constant(Runtime runtime) throws Exception {
        runtime.exec("/usr/bin/true");
    }

    void arrayOverload(Runtime runtime) throws Exception {
        runtime.exec(new String[] { System.getenv("COMMAND") });
    }

    void unrelatedSameNames(SameNameRuntime runtime) {
        runtime.exec(SameNameSystem.getenv("COMMAND"));
    }
}
JAVA

[[ -f "$bundle/index.json" ]] || { echo "selected bundle has no index.json: $bundle" >&2; exit 2; }
mkdir -p -- "$pack_cache"
cache_write_probe=$(mktemp "$pack_cache/.bifrost-write-test.XXXXXX")
rm -f -- "$cache_write_probe"
cp "$selection_receipt" "$scratch/open-packs-receipt.json"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'selection_id=%s\n' "$selection_id" >> "$GITHUB_OUTPUT"
fi

run_scan() {
  local label=$1
  local mounted_java_home=/jdk
  local -a open_semantic_env=()
  if [[ "$label" == "missing" ]]; then
    mounted_java_home=
  fi
  if [[ "$label" == "missing" || "$label" == "positive" ]]; then
    open_semantic_env+=(
      BIFROST_SEMANTIC_PACK_CACHE_ROOT=/open-packs/cache
      BIFROST_OPEN_SEMANTIC_PACK_BUNDLE=/open-packs/semantic
    )
  fi
  set +e
  docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$(dirname "$bifrost"),dst=/release,readonly" \
    --mount "type=bind,src=$java_home,dst=/jdk,readonly" \
    --mount "type=bind,src=$bundle,dst=/open-packs/semantic,readonly" \
    --mount "type=bind,src=$policy_root,dst=/open-packs/policy,readonly" \
    --mount "type=bind,src=$pack_cache,dst=/open-packs/cache" \
    --mount "type=bind,src=$scratch,dst=/work" \
    ubuntu:22.04 \
    env -i PATH=/usr/bin:/bin HOME=/work/empty-home USERPROFILE=/work/empty-home \
      JAVA_HOME="$mounted_java_home" BIFROST_SEMANTIC_PACK_DOWNLOAD=off \
      BIFROST_OPEN_POLICY_PACK_ROOT=/open-packs/policy \
      "${open_semantic_env[@]}" \
      "/release/$(basename "$bifrost")" --root /work/workspace --policy \
      --policy-id bifrost.security.java.system-getenv-to-runtime-exec \
      --format json --fail-on never --evaluation-date 2026-09-17 \
      > "$scratch/$label.json" 2> "$scratch/$label.stderr"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$scratch/$label.status"
  if [[ ! -s "$scratch/$label.json" ]]; then
    echo "scan '$label' produced no JSON (exit $status)" >&2
    cat "$scratch/$label.stderr" >&2
    return 1
  fi
}

# Missing explicit Java toolchain state must remain incomplete while using the
# exact integrity-verified external pack set selected for this engine profile.
run_scan missing

"$installer" verify "$bundle" > "$scratch/bundle-verify.txt"
sed -n '1p' "$scratch/bundle-verify.txt"
"$installer" install "$bundle" "$catalog"
"$installer" list "$catalog" --format json > "$scratch/inventory.json"

node - "$bundle/index.json" "$scratch/inventory.json" <<'NODE'
const fs = require("node:fs");
const [indexPath, inventoryPath] = process.argv.slice(2);
const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));
const inventory = JSON.parse(fs.readFileSync(inventoryPath, "utf8"));
const expected = new Set(index.packs.map((pack) => pack.pack_id));
const installed = new Set(inventory.installed.map((pack) => pack.pack_id));
for (const id of expected) {
  if (!installed.has(id)) throw new Error(`release pack was not installed: ${id}`);
}
for (const id of [
  "bifrost.jdk",
  "bifrost.kotlin-stdlib",
  "bifrost.python-stdlib",
  "bifrost.python-stdlib-assertions",
  "bifrost.rust-stdlib",
  "bifrost.scala-library",
  "bifrost.typescript-stdlib",
]) {
  if (!expected.has(id)) throw new Error(`release bundle omitted audited language pack: ${id}`);
}
NODE

run_scan positive

mv "$catalog" "$workspace/.bifrost/semantic-pack-catalog-valid"
mkdir -p "$catalog"
printf 'not a sqlite catalog\n' > "$catalog/catalog.db"
run_scan corrupt

rm -rf "$catalog"
cp -a "$workspace/.bifrost/semantic-pack-catalog-valid" "$catalog"
python3 - "$catalog/catalog.db" <<'PY'
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA user_version = 2147483647")
connection.commit()
connection.close()
PY
run_scan incompatible

node - "$scratch" "$policy_manifest" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const root = process.argv[2];
const readStatus = (label) => Number(fs.readFileSync(path.join(root, `${label}.status`), "utf8").trim());
const readJson = (label) => JSON.parse(fs.readFileSync(path.join(root, `${label}.json`), "utf8"));

const report = readJson("positive");
const run = report.runs.find((entry) => entry.policy_id === "bifrost.security.java.system-getenv-to-runtime-exec");
if (!run) throw new Error("staged binary omitted the Java getenv-to-exec policy run");
if (!report.packs.decisions.some((decision) => decision.pack.startsWith("bifrost.jdk@") && decision.status === "selected")) {
  throw new Error("the installed curated JDK pack was not selected from exact Linux toolchain evidence");
}
const manifest = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const policies = manifest.policies.filter((policy) => policy.id === run.policy_id);
if (manifest.id !== "bifrost.security" || policies.length !== 1 ||
    !/^[0-9a-f]{64}$/.test(policies[0].resolved_semantic_hash)) {
  throw new Error("release manifest omitted a unique, exact Java getenv-to-exec policy identity");
}
if (run.policy_hash !== policies[0].resolved_semantic_hash) {
  throw new Error(`unexpected Java getenv-to-exec policy hash: ${run.policy_hash}`);
}

const positiveStatus = readStatus("positive");
const reasons = run.completion?.reasons ?? [];
const diagnostics = run.diagnostics ?? [];
const knownDispatchPartial =
  positiveStatus === 2 &&
  run.findings.length === 0 &&
  run.completion?.type === "inconclusive" &&
  reasons.length === 1 &&
  reasons[0] === "partial_discovery" &&
  diagnostics.length === 1 &&
  diagnostics[0].code?.type === "evaluation_failure" &&
  diagnostics[0].severity === "warning" &&
  diagnostics[0].impact === "run_incomplete" &&
  diagnostics[0].family === "evaluation_failure" &&
  diagnostics[0].message.includes("/analysis/sinks/entries/runtime-exec-command/selector") &&
  diagnostics[0].message.includes("call_binding_dispatch_partial") &&
  diagnostics[0].message.includes("UnsupportedExpression");

let verdict;
if (positiveStatus === 0 && run.completion?.type === "complete" && run.findings.length === 1) {
  const evidence = run.findings[0].evidence.evidence;
  if (evidence.source_endpoint.entry_id !== "environment-variable") throw new Error("wrong source endpoint");
  if (evidence.sink_endpoint.entry_id !== "runtime-exec-command") throw new Error("wrong sink endpoint");
  verdict = "passed";
} else if (knownDispatchPartial) {
  verdict = "unreliable";
  console.error(
    "staged policy smoke is unreliable: exact Runtime.exec(String) dispatch proof is partial (recorded, non-blocking)",
  );
} else {
  throw new Error(
    `unexpected staged policy result: exit=${positiveStatus} completion=${JSON.stringify(run.completion)} findings=${run.findings.length} diagnostics=${JSON.stringify(diagnostics)}`,
  );
}

for (const label of ["missing", "corrupt", "incompatible"]) {
  if (readStatus(label) === 0) throw new Error(`${label} catalog was reported clean`);
  const value = readJson(label);
  if (value.runs?.some((candidate) => candidate.completion?.type === "complete" && candidate.findings?.length === 0)) {
    throw new Error(`${label} catalog produced a complete clean policy run`);
  }
}

const missing = readJson("missing");
if (missing.packs?.decisions?.some((decision) => decision.pack.startsWith("bifrost.jdk@") && decision.status === "selected")) {
  throw new Error("the missing-JAVA_HOME acceptance unexpectedly selected a curated JDK pack");
}

fs.writeFileSync(
  path.join(root, "policy-smoke-status.json"),
  `${JSON.stringify({
    schemaVersion: 1,
    policyId: run.policy_id,
    policyHash: run.policy_hash,
    verdict,
    processExit: positiveStatus,
    completion: run.completion,
    findingCount: run.findings.length,
    diagnostics,
  }, null, 2)}\n`,
);
NODE

echo "offline semantic-pack installer acceptance passed"
