import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { checkInventory, obtainArchive, readPin, updatePin } from "./derive-pack-approval-inventory.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture({ inventory = "inventory-v1\n", committed = inventory } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "pack-approval-test-"));
  const archive = Buffer.from("fake archive bytes");
  await fs.writeFile(path.join(dir, "archive.tgz"), archive);
  const pin = {
    channel: "public-semantic-packs",
    repository: "BrokkAi/bifrost-packs",
    releaseTag: "packs/v1.2.3",
    assetName: "bifrost.public.packs-1.2.3-native.tar.gz",
    archiveSha256: sha(archive),
    inventoryPath: "committed.json",
  };
  await fs.writeFile(path.join(dir, "pin.json"), JSON.stringify(pin));
  await fs.writeFile(path.join(dir, "committed.json"), committed);
  // Stub producer: records argv/cwd/env and writes deterministic bytes.
  const stub = path.join(dir, "stub-bifrost.mjs");
  await fs.writeFile(
    stub,
    `#!/usr/bin/env node
import fs from "node:fs";
import { createHash } from "node:crypto";
const a = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(path.join(dir, "argv.json"))}, JSON.stringify({ a, cwd: process.cwd(), env: Object.keys(process.env).sort() }));
const out = a[a.indexOf("--output") + 1];
const bytes = ${JSON.stringify(inventory)};
fs.writeFileSync(out, bytes);
console.log(JSON.stringify({ inventory_path: out, inventory_sha256: createHash("sha256").update(bytes).digest("hex") }));
`,
    { mode: 0o755 },
  );
  return { dir, pin, stub, pinPath: path.join(dir, "pin.json"), archive: path.join(dir, "archive.tgz") };
}

test("matching committed inventory passes and the producer gets the frozen command line", async () => {
  const f = await fixture();
  const result = await checkInventory({ bifrost: f.stub, pinPath: f.pinPath, archiveOverride: f.archive, root: f.dir });
  assert.equal(result.inventorySha256, sha("inventory-v1\n"));
  const seen = JSON.parse(await fs.readFile(path.join(f.dir, "argv.json"), "utf8"));
  assert.deepEqual(seen.a.slice(0, 1), ["prepare-pack-approval-inventory"]);
  assert.equal(seen.a[seen.a.indexOf("--archive-sha256") + 1], f.pin.archiveSha256);
  assert.equal(seen.a[seen.a.indexOf("--channel") + 1], "public-semantic-packs");
  assert.equal(seen.a[seen.a.indexOf("--release-tag") + 1], "packs/v1.2.3");
  assert.notEqual(seen.cwd, f.dir);
  assert.ok(!seen.env.some((k) => k.startsWith("PACK_")), "no PACK_* env reaches the producer");
});

test("a committed inventory that differs from the re-derived bytes fails", async () => {
  const f = await fixture({ committed: "inventory-v0\n" });
  await assert.rejects(
    checkInventory({ bifrost: f.stub, pinPath: f.pinPath, archiveOverride: f.archive, root: f.dir }),
    /drifted from packs\/v1\.2\.3/u,
  );
});

test("an archive that does not match the pin is refused before the producer runs", async () => {
  const f = await fixture();
  await fs.writeFile(f.archive, "tampered");
  await assert.rejects(
    checkInventory({ bifrost: f.stub, pinPath: f.pinPath, archiveOverride: f.archive, root: f.dir }),
    /does not match the pinned/u,
  );
  await assert.rejects(fs.access(path.join(f.dir, "argv.json")));
});

test("a missing committed inventory fails", async () => {
  const f = await fixture();
  await fs.rm(path.join(f.dir, "committed.json"));
  await assert.rejects(
    checkInventory({ bifrost: f.stub, pinPath: f.pinPath, archiveOverride: f.archive, root: f.dir }),
    /does not exist/u,
  );
});

test("pin validation rejects malformed pins", async () => {
  const f = await fixture();
  for (const patch of [{ archiveSha256: "ABC" }, { releaseTag: "v1" }, { assetName: "../x" }, { channel: "" }]) {
    await fs.writeFile(f.pinPath, JSON.stringify({ ...f.pin, ...patch }));
    assert.throws(() => readPin(f.pinPath));
  }
});

test("update-pin writes the published digest only when the download matches it", async () => {
  const f = await fixture();
  const bytes = Buffer.from("new archive");
  const urls = [];
  const pin = await updatePin({
    tag: "packs/v1.3.0",
    pinPath: f.pinPath,
    fetchText: async (u) => { urls.push(u); return `${sha(bytes)}  bifrost.public.packs-1.3.0-native.tar.gz\n`; },
    fetchBytes: async (u) => { urls.push(u); return bytes; },
  });
  assert.equal(pin.assetName, "bifrost.public.packs-1.3.0-native.tar.gz");
  assert.equal(readPin(f.pinPath).archiveSha256, sha(bytes));
  assert.ok(urls.every((u) => u.includes("BrokkAi/bifrost-packs/releases/download/packs/v1.3.0/")));
  await assert.rejects(
    updatePin({ tag: "packs/v1.4.0", pinPath: f.pinPath, fetchText: async () => "0".repeat(64), fetchBytes: async () => bytes }),
    /published checksum/u,
  );
});

test("obtainArchive accepts only the pinned bytes", async () => {
  const f = await fixture();
  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "pack-approval-scratch-"));
  const out = await obtainArchive(f.pin, scratch, f.archive);
  assert.equal(sha(await fs.readFile(out)), f.pin.archiveSha256);
});
