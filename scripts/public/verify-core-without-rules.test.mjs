import assert from "node:assert/strict";
import test from "node:test";
import { verifyCoreWithoutRules } from "./verify-core-without-rules.mjs";

const identity = "a".repeat(40);
function engine({ packs = [], findings = [], restoresRule = false, buildIdentity = identity } = {}) {
  return async (_binary, args, { env }) => {
    assert.equal(env.BIFROST_OPEN_POLICY_PACK_ROOT, undefined);
    if (args[0] === "--build-identity") return { stdout: buildIdentity };
    if (args.includes("--list-builtin-policies")) {
      assert.deepEqual(args, ["scan", "--list-builtin-policies"]);
      return { stdout: JSON.stringify({ schema_version: 2, packs }) };
    }
    if (args[0] === "scan") return {
      stdout: JSON.stringify({ schema_version: 1, status: "not-evaluated", reason: "no-active-rule-packs", findings }), stderr: "no rules were evaluated",
    };
    if (restoresRule) return { stdout: "restored product rule" };
    throw Object.assign(new Error("absent rule"), { code: 2, stderr: "unknown policy id" });
  };
}

test("core qualification records an empty catalog separately from unqualified host content", async () => {
  const receipt = await verifyCoreWithoutRules("bifrost", identity, { exec: engine() });
  assert.equal(receipt.core.status, "verified");
  assert.equal(receipt.core.active_rule_packs, 0);
  assert.equal(receipt.external_content.status, "not-qualified");
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
test("a different binary build identity cannot pass core qualification", async () => {
  await assert.rejects(verifyCoreWithoutRules("bifrost", identity, { exec: engine({ buildIdentity: "b".repeat(40) }) }), /identity differs/u);
});
