import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  isMainModule,
  launch,
  linuxLibc,
  nativeBinaryPath,
  platformPackageName,
  resolveBundle,
} from "../launcher/bifrost.js";

test("recognizes npm's linked executable", () => {
  let resolved;
  assert.equal(
    isMainModule("/tmp/node_modules/.bin/bifrost", (entrypoint) => {
      resolved = entrypoint;
      return new URL("../launcher/bifrost.js", import.meta.url).pathname;
    }),
    true,
  );
  assert.equal(resolved, "/tmp/node_modules/.bin/bifrost");
});

test("detects the Linux C library", () => {
  assert.equal(linuxLibc({ header: { glibcVersionRuntime: "2.39" } }), "gnu");
  assert.equal(linuxLibc({ header: {} }), "musl");
});

test("selects each published native package", () => {
  assert.equal(platformPackageName("darwin", "arm64"), "@brokkai/bifrost-darwin-universal");
  assert.equal(platformPackageName("darwin", "x64"), "@brokkai/bifrost-darwin-universal");
  assert.equal(platformPackageName("linux", "x64", "gnu"), "@brokkai/bifrost-linux-x64-gnu");
  assert.equal(platformPackageName("linux", "x64", "musl"), "@brokkai/bifrost-linux-x64-musl");
  assert.equal(platformPackageName("linux", "arm64", "gnu"), "@brokkai/bifrost-linux-arm64-gnu");
  assert.equal(platformPackageName("android", "arm64"), "@brokkai/bifrost-android-arm64");
  assert.equal(platformPackageName("win32", "x64"), "@brokkai/bifrost-win32-x64");
  assert.equal(platformPackageName("win32", "arm64"), "@brokkai/bifrost-win32-arm64");
});

test("rejects an unsupported platform", () => {
  assert.throws(() => platformPackageName("linux", "arm64", "musl"), /does not publish/);
});

test("resolves the native package root", () => {
  const bundle = resolveBundle(
    (name) => {
      assert.equal(name, "@brokkai/bifrost-linux-x64-gnu/package.json");
      return "/tmp/node_modules/@brokkai/bifrost-linux-x64-gnu/package.json";
    },
    "linux",
    "x64",
    "gnu",
  );
  assert.equal(bundle, "/tmp/node_modules/@brokkai/bifrost-linux-x64-gnu");
});

test("uses the platform executable name", () => {
  assert.equal(nativeBinaryPath("/tmp/bundle", "linux"), "/tmp/bundle/bin/bifrost");
  assert.equal(nativeBinaryPath("C:\\bundle", "win32"), "C:\\bundle/bin/bifrost.exe");
});

test("forwards all CLI arguments unchanged and returns process status", () => {
  const child = new EventEmitter();
  child.kill = () => true;
  const forwardedArgs = [
    "--future-native-flag",
    "value with spaces",
    "--option=value",
    "--",
    "--literal-after-separator",
  ];
  let invocation;
  let exitCode;
  launch(
    "/tmp/bundle",
    forwardedArgs,
    "linux",
    (binary, args, options) => {
      invocation = { binary, args, options };
      return child;
    },
    (code) => {
      exitCode = code;
    },
  );
  assert.equal(invocation.binary, "/tmp/bundle/bin/bifrost");
  assert.deepEqual(invocation.args, forwardedArgs);
  assert.equal(invocation.options.stdio, "inherit");
  child.emit("exit", 17, null);
  assert.equal(exitCode, 17);
});

test("uses the conventional status for a signal", () => {
  const child = new EventEmitter();
  child.kill = () => true;
  let exitCode;
  launch("/tmp/bundle", [], "linux", () => child, (code) => {
    exitCode = code;
  });
  child.emit("exit", null, "SIGINT");
  assert.equal(exitCode, 130);
});
