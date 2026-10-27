import assert from "node:assert/strict";
import test from "node:test";
import { verifyCoreWithoutRules } from "./verify-core-without-rules.mjs";

const identity = "a".repeat(40);
const incomplete = "bifrost: policy evaluation was incomplete or invalid; see the emitted report for details\n";
// Host channels through which the real binary installs rule content, plus one
// it does not read yet, which stands for a channel a later engine adds.
const ruleRoots = [
  "BIFROST_POLICY_PACK_ROOT", "BIFROST_OPEN_POLICY_PACK_ROOT", "BIFROST_POLICY_BUNDLE_ROOT", "BIFROST_FUTURE_RULE_ROOT",
];
function engine({ packs = [], findings = [], restoresRule = false, evaluatesRule = false, buildIdentity = identity } = {}) {
  return async (_binary, args, { env }) => {
    if (args[0] === "--build-identity") return { stdout: buildIdentity };
    if (args.includes("--list-builtin-policies")) {
      assert.deepEqual(args, ["scan", "--list-builtin-policies"]);
      return { stdout: JSON.stringify({ schema_version: 2, packs }) };
    }
    if (args[0] === "scan") return {
      stdout: JSON.stringify({ schema_version: 1, status: "not-evaluated", reason: "no-active-rule-packs", findings }), stderr: "no rules were evaluated",
    };
    if (restoresRule) return { stdout: "restored product rule" };
    // A host root, or acquisition of the public rules release, installs the
    // named rule; it then runs on the empty root and reports an incomplete result.
    const hostRule = ruleRoots.some((name) => env[name] !== undefined) || env.BIFROST_OPEN_PACKS_DISABLE !== "1";
    if (evaluatesRule || hostRule) throw Object.assign(new Error("incomplete"), { code: 2, stderr: incomplete });
    throw Object.assign(new Error("absent rule"), {
      code: 2, stderr: "unknown built-in policy id `bifrost.correctness.dynamic-evaluation`\n",
    });
  };
}

test("core qualification records an empty catalog separately from unqualified host content", async () => {
  const receipt = await verifyCoreWithoutRules("bifrost", identity, { exec: engine() });
  assert.equal(receipt.core.status, "verified");
  assert.equal(receipt.core.active_rule_packs, 0);
  assert.equal(receipt.external_content.status, "not-qualified");
});
// Hard-won (Release analyzer validation run 40198999149): the binary acquired
// the public rules release, so the absent rule ran and reported an incomplete
// result instead of an unknown id. The check passed only when anonymous
// discovery happened to fail.
test("host rule channels in the parent environment cannot reach the core check", async () => {
  const names = [...ruleRoots, "BIFROST_OPEN_PACKS_DISABLE"];
  const saved = names.map((name) => [name, process.env[name]]);
  for (const name of ruleRoots) process.env[name] = "/host/rules";
  process.env.BIFROST_OPEN_PACKS_DISABLE = "0";
  try {
    const receipt = await verifyCoreWithoutRules("bifrost", identity, { exec: engine() });
    assert.equal(receipt.core.status, "verified");
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});
test("embedded product content cannot pass core qualification", async () => {
  await assert.rejects(verifyCoreWithoutRules("bifrost", identity, { exec: engine({ packs: [{ id: "product" }] }) }), /still delivers product rules/u);
});
test("a scan that evaluates a rule cannot pass empty-core qualification", async () => {
  await assert.rejects(verifyCoreWithoutRules("bifrost", identity, { exec: engine({ findings: [{ id: "product" }] }) }), /unexpectedly evaluated rules/u);
});
test("silent product-rule restoration cannot pass core qualification", async () => {
  await assert.rejects(verifyCoreWithoutRules("bifrost", identity, { exec: engine({ restoresRule: true }) }), /silently restored/u);
});
test("an incomplete run of a restored rule cannot pass as its rejection", async () => {
  await assert.rejects(verifyCoreWithoutRules("bifrost", identity, { exec: engine({ evaluatesRule: true }) }), /did not match/u);
});
test("a different binary build identity cannot pass core qualification", async () => {
  await assert.rejects(verifyCoreWithoutRules("bifrost", identity, { exec: engine({ buildIdentity: "b".repeat(40) }) }), /identity differs/u);
});
