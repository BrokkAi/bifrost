import assert from "node:assert/strict";
import test from "node:test";

import { packageExists, publishOrRecover, publishTarball } from "../scripts/publish-release.mjs";

test("treats a registry 404 as a version that is not visible", () => {
  const exists = packageExists("@brokkai/bifrost-linux-arm64-gnu", "0.8.22", () => ({
    status: 1,
    stdout: "",
    stderr: "npm error code E404\n",
  }));
  assert.equal(exists, false);
});

test("does not treat other npm view errors as a missing version", () => {
  assert.throws(
    () =>
      packageExists("@brokkai/bifrost-linux-arm64-gnu", "0.8.22", () => ({
        status: 1,
        stdout: "",
        stderr: "npm error code E401\n",
      })),
    /npm view.*failed/s,
  );
});

test("keeps npm publish attached to the terminal for browser authentication", () => {
  let invocation;
  const published = publishTarball("/tmp/package.tgz", (command, args, options) => {
    invocation = { command, args, options };
    return { status: 0 };
  });
  assert.equal(published, true);
  assert.equal(invocation.command, "npm");
  assert.deepEqual(invocation.args, ["publish", "/tmp/package.tgz", "--access", "public"]);
  assert.equal(invocation.options.stdio, "inherit");
});

test("checks registry visibility after a failed publish", async () => {
  let waitedFor;
  await publishOrRecover(
    { packageName: "@brokkai/bifrost-linux-arm64-gnu", tarball: "/tmp/package.tgz" },
    "0.8.22",
    () => false,
    () => false,
    async (packageName, version) => {
      waitedFor = `${packageName}@${version}`;
    },
    () => {},
  );
  assert.equal(waitedFor, "@brokkai/bifrost-linux-arm64-gnu@0.8.22");
});
