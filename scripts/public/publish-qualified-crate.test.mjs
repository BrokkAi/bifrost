import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  framePublishRequest,
  parsePublishRequest,
  publishEndpoint,
  publishFrameHeader,
  publishQualifiedCrate,
  sha256Hex,
} from "./publish-qualified-crate.mjs";

function requestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

async function fakeRegistry(handler) {
  const server = createServer((request, response) => {
    void handler(request, response).catch((error) => {
      response.destroy(error);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => {
      server.closeAllConnections();
      server.close((error) => (error ? reject(error) : resolve()));
    }),
  };
}

function fixtureFiles() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "publish-qualified-crate-"));
  const metadata = Buffer.from('{"name":"example","vers":"1.2.3","deps":[]}\n', "utf8");
  const crate = Buffer.from([0x1f, 0x8b, 0x00, 0xff, 0x0a, 0x7f, 0x42]);
  const metadataPath = path.join(directory, "metadata.json");
  const cratePath = path.join(directory, "example-1.2.3.crate");
  fs.writeFileSync(metadataPath, metadata);
  fs.writeFileSync(cratePath, crate);
  return { directory, metadata, crate, metadataPath, cratePath };
}

test("publishes exact metadata and crate bytes with the documented framing", async () => {
  const fixture = fixtureFiles();
  let observed;
  const registry = await fakeRegistry(async (request, response) => {
    observed = {
      method: request.method,
      path: request.url,
      authorization: request.headers.authorization,
      contentType: request.headers["content-type"],
      accept: request.headers.accept,
      contentLength: request.headers["content-length"],
      body: await requestBody(request),
    };
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      warnings: {
        invalid_categories: ["old-category"],
        invalid_badges: [],
        other: ["kept exactly"],
      },
    }));
  });

  try {
    const result = await publishQualifiedCrate({
      metadataPath: fixture.metadataPath,
      cratePath: fixture.cratePath,
      expectedSha256: sha256Hex(fixture.crate),
      registryBaseUrl: registry.baseUrl,
      token: "token trusted-publishing-output",
      timeoutMs: 1_000,
    });
    assert.deepEqual(result.warnings, {
      invalid_categories: ["old-category"],
      invalid_badges: [],
      other: ["kept exactly"],
    });
    assert.equal(result.sha256, sha256Hex(fixture.crate));
    assert.equal(observed.method, "PUT");
    assert.equal(observed.path, "/api/v1/crates/new");
    assert.equal(observed.authorization, "token trusted-publishing-output");
    assert.equal(observed.contentType, "application/octet-stream");
    assert.equal(observed.accept, "application/json");
    assert.equal(observed.contentLength, String(observed.body.length));
    const parsed = parsePublishRequest(observed.body);
    assert.deepEqual(parsed.metadataBytes, fixture.metadata);
    assert.deepEqual(parsed.crateBytes, fixture.crate);
  } finally {
    await registry.close();
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects a checksum mismatch before making a network request", async () => {
  const fixture = fixtureFiles();
  let requests = 0;
  const registry = await fakeRegistry(async (request, response) => {
    requests += 1;
    request.resume();
    response.writeHead(500);
    response.end();
  });
  try {
    await assert.rejects(
      publishQualifiedCrate({
        metadataPath: fixture.metadataPath,
        cratePath: fixture.cratePath,
        expectedSha256: "0".repeat(64),
        registryBaseUrl: registry.baseUrl,
        token: "token unused",
      }),
      (error) => error.message.includes("Crate checksum mismatch"),
    );
    assert.equal(requests, 0);
  } finally {
    await registry.close();
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("reports all API errors and does not retry non-2xx responses", async () => {
  const fixture = fixtureFiles();
  let requests = 0;
  const registry = await fakeRegistry(async (request, response) => {
    requests += 1;
    request.resume();
    response.writeHead(422, { "content-type": "application/json" });
    response.end(JSON.stringify({ errors: [{ detail: "first error" }, { detail: "second error" }] }));
  });
  try {
    await assert.rejects(
      publishQualifiedCrate({
        metadataPath: fixture.metadataPath,
        cratePath: fixture.cratePath,
        registryBaseUrl: registry.baseUrl,
        token: "token exact",
      }),
      (error) => {
        assert.equal(error.status, 422);
        assert.deepEqual(error.errors, [{ detail: "first error" }, { detail: "second error" }]);
        assert.match(error.message, /first error; second error/u);
        return true;
      },
    );
    assert.equal(requests, 1);
  } finally {
    await registry.close();
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects API errors even when the HTTP status is successful", async () => {
  const fixture = fixtureFiles();
  const registry = await fakeRegistry(async (request, response) => {
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ errors: [{ detail: "application-level failure" }] }));
  });
  try {
    await assert.rejects(
      publishQualifiedCrate({
        metadataPath: fixture.metadataPath,
        cratePath: fixture.cratePath,
        registryBaseUrl: registry.baseUrl,
        token: "token exact",
      }),
      /application-level failure/u,
    );
  } finally {
    await registry.close();
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("rejects truncated and oversized frames", () => {
  assert.throws(() => parsePublishRequest(Buffer.alloc(3)), /missing metadata length/u);
  assert.throws(
    () => parsePublishRequest(Buffer.from([5, 0, 0, 0, 1])),
    /metadata exceeds the request body/u,
  );
  assert.throws(
    () => parsePublishRequest(Buffer.from([0, 0, 0, 0, 5, 0, 0, 0])),
    /crate exceeds the request body/u,
  );
  assert.throws(
    () => parsePublishRequest(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 1])),
    /trailing bytes/u,
  );
  assert.throws(() => publishFrameHeader(0x1_0000_0000, 0), /Metadata length/u);
  assert.throws(() => publishFrameHeader(0, 0x1_0000_0000), /Crate length/u);
});

test("times out once without automatically retrying an ambiguous request", async () => {
  const fixture = fixtureFiles();
  let requests = 0;
  const registry = await fakeRegistry(async (request, response) => {
    requests += 1;
    request.resume();
    await new Promise((resolve) => setTimeout(resolve, 250));
    if (!response.writableEnded) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ warnings: {} }));
    }
  });
  try {
    await assert.rejects(
      publishQualifiedCrate({
        metadataPath: fixture.metadataPath,
        cratePath: fixture.cratePath,
        registryBaseUrl: registry.baseUrl,
        token: "token exact",
        timeoutMs: 20,
      }),
      /timed out after 20 milliseconds; no retry was attempted/u,
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(requests, 1);
  } finally {
    await registry.close();
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("frames metadata and archive without changing either byte sequence", () => {
  const metadata = Buffer.from('{"name":"bytes"}\n', "utf8");
  const crate = Buffer.from([0x00, 0xff, 0x80, 0x0a]);
  const frame = framePublishRequest(metadata, crate);
  const parsed = parsePublishRequest(frame);
  assert.deepEqual(parsed.metadataBytes, metadata);
  assert.deepEqual(parsed.crateBytes, crate);
  assert.equal(createHash("sha256").update(parsed.crateBytes).digest("hex"), sha256Hex(crate));
  assert.deepEqual(publishEndpoint("https://example.test/"), new URL("https://example.test/api/v1/crates/new"));
});
