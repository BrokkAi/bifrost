import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { packageExists, publishTarball } from "../scripts/publish-release.mjs";

function publishProcess(stderr, status = 1) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  queueMicrotask(() => {
    child.stderr.emit("data", stderr);
    child.emit("close", status);
  });
  return child;
}

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

test("continues waiting when npm already accepted a version", async () => {
  let message;
  await publishTarball(
    "/tmp/brokkai-bifrost-linux-arm64-gnu-0.8.22.tgz",
    () =>
      publishProcess(
        "npm error code E403\nnpm error You cannot publish over the previously published versions: 0.8.22.\n",
      ),
    () => {},
    (value) => {
      message = `${message ?? ""}${value}`;
    },
  );
  assert.match(message, /already accepted.*waiting for registry visibility/);
});

test("rejects a publish permission error", async () => {
  await assert.rejects(
    publishTarball(
      "/tmp/brokkai-bifrost-linux-arm64-gnu-0.8.22.tgz",
      () => publishProcess("npm error code E403\nnpm error permission denied\n"),
      () => {},
      () => {},
    ),
    /npm publish failed/,
  );
});
