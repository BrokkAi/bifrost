#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 BIFROST INSTALLER BUNDLE JAVA_HOME SCRATCH_ROOT" >&2
  exit 2
fi

bifrost=$(realpath "$1")
installer=$(realpath "$2")
bundle=$(realpath "$3")
java_home=$(realpath "$4")
scratch=$(realpath -m "$5")

for executable in "$bifrost" "$installer"; do
  [[ -x "$executable" ]] || { echo "not executable: $executable" >&2; exit 2; }
done
[[ -f "$bundle/index.json" ]] || { echo "bundle has no index.json: $bundle" >&2; exit 2; }
[[ -x "$java_home/bin/java" && -d "$java_home/jmods" ]] || {
  echo "JAVA_HOME is not a complete JDK: $java_home" >&2
  exit 2
}

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
    void positive() throws Exception {
        String command = System.getenv("COMMAND");
        Runtime runtime = Runtime.getRuntime();
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

run_scan() {
  local label=$1
  local mounted_java_home=/jdk
  if [[ "$label" == "missing" ]]; then
    mounted_java_home=
  fi
  set +e
  docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$(dirname "$bifrost"),dst=/release,readonly" \
    --mount "type=bind,src=$java_home,dst=/jdk,readonly" \
    --mount "type=bind,src=$scratch,dst=/work" \
    ubuntu:22.04 \
    env -i PATH=/usr/bin:/bin HOME=/work/empty-home USERPROFILE=/work/empty-home \
      JAVA_HOME="$mounted_java_home" BIFROST_SEMANTIC_PACK_DOWNLOAD=off \
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

# Missing explicit state must fail before installation, even though the exact
# runtime toolchain is available and the facade's acquisition provider exists.
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

node - "$scratch" <<'NODE'
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
if (run.findings.length !== 1) throw new Error(`expected exactly one finding, got ${run.findings.length}`);
const evidence = run.findings[0].evidence.evidence;
if (evidence.source_endpoint.entry_id !== "environment-variable") throw new Error("wrong source endpoint");
if (evidence.sink_endpoint.entry_id !== "runtime-exec-command") throw new Error("wrong sink endpoint");
if (readStatus("positive") === 0 && run.completion.type !== "complete") {
  throw new Error("a zero exit status cannot carry an incomplete positive run");
}

for (const label of ["missing", "corrupt", "incompatible"]) {
  if (readStatus(label) === 0) throw new Error(`${label} catalog was reported clean`);
  const value = readJson(label);
  if (value.runs?.some((candidate) => candidate.completion?.type === "complete" && candidate.findings?.length === 0)) {
    throw new Error(`${label} catalog produced a complete clean policy run`);
  }
}
NODE

echo "offline semantic-pack installer acceptance passed"
