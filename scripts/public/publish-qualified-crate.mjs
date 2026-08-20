#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import { TextDecoder } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_U32 = 0xffffffff;
const DEFAULT_REGISTRY_BASE_URL = "https://crates.io";
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const USER_AGENT = "bifrost-qualified-crate-publisher/1";
const SHA256 = /^[0-9a-f]{64}$/u;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

export class PublishError extends Error {
  constructor(message, { status, body, errors, cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PublishError";
    if (status !== undefined) this.status = status;
    if (body !== undefined) this.responseBody = body;
    if (errors !== undefined) this.errors = errors;
  }
}

function bytes(value, name) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`${name} must be a Buffer or Uint8Array.`);
}

function validateLength(length, name) {
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_U32) {
    throw new RangeError(`${name} length must be an integer from 0 through ${MAX_U32}.`);
  }
  return length;
}

function lengthBytes(length, name) {
  const output = Buffer.allocUnsafe(4);
  output.writeUInt32LE(validateLength(length, name), 0);
  return output;
}

export function publishFrameHeader(metadataLength, crateLength) {
  return Buffer.concat([
    lengthBytes(metadataLength, "Metadata"),
    lengthBytes(crateLength, "Crate"),
  ]);
}

export function validateMetadataJson(metadataBytes) {
  const metadata = bytes(metadataBytes, "Metadata bytes");
  let value;
  try {
    value = JSON.parse(UTF8_DECODER.decode(metadata));
  } catch (error) {
    throw new TypeError(`Metadata must be valid UTF-8 JSON: ${error.message}`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Metadata JSON must be an object.");
  }
  return metadata;
}

export function framePublishRequest(metadataBytes, crateBytes) {
  const metadata = validateMetadataJson(metadataBytes);
  const crate = bytes(crateBytes, "Crate bytes");
  const header = publishFrameHeader(metadata.length, crate.length);
  return Buffer.concat([
    header.subarray(0, 4),
    metadata,
    header.subarray(4, 8),
    crate,
  ]);
}

export function parsePublishRequest(body) {
  const frame = bytes(body, "Publish request body");
  if (frame.length < 4) throw new RangeError("Truncated publish request: missing metadata length.");

  const metadataLength = frame.readUInt32LE(0);
  const metadataStart = 4;
  if (metadataLength > frame.length - metadataStart) {
    throw new RangeError("Truncated publish request: metadata exceeds the request body.");
  }

  const metadataEnd = metadataStart + metadataLength;
  if (frame.length - metadataEnd < 4) {
    throw new RangeError("Truncated publish request: missing crate length.");
  }

  const crateLength = frame.readUInt32LE(metadataEnd);
  const crateStart = metadataEnd + 4;
  if (crateLength > frame.length - crateStart) {
    throw new RangeError("Truncated publish request: crate exceeds the request body.");
  }

  const end = crateStart + crateLength;
  if (end !== frame.length) {
    throw new RangeError(`Invalid publish request: ${frame.length - end} trailing bytes.`);
  }

  return {
    metadataBytes: frame.subarray(metadataStart, metadataEnd),
    crateBytes: frame.subarray(crateStart, end),
  };
}

export function sha256Hex(value) {
  return createHash("sha256").update(bytes(value, "Bytes")).digest("hex");
}

function expectedChecksum(value) {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError("Expected SHA-256 must be 64 lowercase hexadecimal characters.");
  }
  return value;
}

export function publishEndpoint(registryBaseUrl = DEFAULT_REGISTRY_BASE_URL) {
  if (typeof registryBaseUrl !== "string" || registryBaseUrl.length === 0) {
    throw new TypeError("Registry base URL must be a non-empty string.");
  }

  let url;
  try {
    url = new URL(registryBaseUrl);
  } catch (error) {
    throw new TypeError(`Invalid registry base URL: ${error.message}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError("Registry base URL must use http or https.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("Registry base URL must not contain credentials, a query, or a fragment.");
  }
  const basePath = url.pathname.replace(/\/+$/u, "");
  url.pathname = `${basePath}/api/v1/crates/new`;
  return url;
}

function timeoutMilliseconds(value) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > MAX_TIMEOUT_MS) {
    throw new RangeError(`Timeout must be an integer from 1 through ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  return value;
}

function authorizationToken(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("A crates.io authorization token is required.");
  }
  if (/[\r\n]/u.test(value)) throw new TypeError("Authorization token contains a newline.");
  return value;
}

function responseObject(raw, status) {
  if (raw.trim().length === 0) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("response JSON must be an object");
    }
    return parsed;
  } catch (error) {
    throw new PublishError(`Registry returned HTTP ${status} with invalid JSON: ${error.message}`, {
      status,
      body: raw,
      cause: error,
    });
  }
}

function errorDetails(errors) {
  return errors
    .map((entry) => {
      if (entry && typeof entry.detail === "string") return entry.detail;
      return JSON.stringify(entry);
    })
    .join("; ");
}

function rejectResponse(response, body) {
  if (Array.isArray(body.errors) && body.errors.length > 0) {
    throw new PublishError(`Registry rejected crate publication: ${errorDetails(body.errors)}`, {
      status: response.status,
      body,
      errors: body.errors,
    });
  }
  if (body.errors !== undefined && !Array.isArray(body.errors)) {
    throw new PublishError("Registry returned an invalid errors field.", {
      status: response.status,
      body,
    });
  }
  if (!response.ok) {
    const detail = JSON.stringify(body);
    throw new PublishError(`Registry returned HTTP ${response.status}: ${detail}`, {
      status: response.status,
      body,
    });
  }
}

export async function publishQualifiedCrate({
  metadataBytes,
  metadataPath,
  crateBytes,
  cratePath,
  expectedSha256,
  registryBaseUrl = DEFAULT_REGISTRY_BASE_URL,
  token = process.env.CARGO_REGISTRY_TOKEN,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (metadataBytes !== undefined && metadataPath !== undefined) {
    throw new TypeError("Provide metadataBytes or metadataPath, not both.");
  }
  if (crateBytes !== undefined && cratePath !== undefined) {
    throw new TypeError("Provide crateBytes or cratePath, not both.");
  }
  const metadata = validateMetadataJson(
    metadataBytes === undefined
      ? fs.readFileSync(requiredPath(metadataPath, "Metadata"))
      : metadataBytes,
  );
  const crate = bytes(
    crateBytes === undefined ? fs.readFileSync(requiredPath(cratePath, "Crate")) : crateBytes,
    "Crate bytes",
  );
  const expected = expectedChecksum(expectedSha256);
  const actual = sha256Hex(crate);
  if (expected !== undefined && actual !== expected) {
    throw new PublishError(`Crate checksum mismatch: expected ${expected}, got ${actual}.`);
  }

  const endpoint = publishEndpoint(registryBaseUrl);
  const authorization = authorizationToken(token);
  const timeout = timeoutMilliseconds(timeoutMs);
  const frame = framePublishRequest(metadata, crate);
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeout);

  let response;
  try {
    response = await fetch(endpoint, {
      method: "PUT",
      headers: {
        Accept: "application/json",
        Authorization: authorization,
        "Content-Length": String(frame.length),
        "Content-Type": "application/octet-stream",
        "User-Agent": USER_AGENT,
      },
      body: frame,
      signal: controller.signal,
    });
    const raw = await response.text();
    const body = responseObject(raw, response.status);
    rejectResponse(response, body);
    return {
      status: response.status,
      warnings: body.warnings ?? {},
      response: body,
      sha256: actual,
    };
  } catch (error) {
    if (timedOut) {
      throw new PublishError(`Crate publication timed out after ${timeout} milliseconds; no retry was attempted.`, {
        cause: error,
      });
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function requiredPath(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${name} path is required.`);
  return value;
}

export function parseCliArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--help" || flag === "-h") return { help: true };
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`Missing value for ${flag}.`);
    switch (flag) {
      case "--metadata-file":
        options.metadataPath = value;
        break;
      case "--crate-file":
        options.cratePath = value;
        break;
      case "--expected-sha256":
        options.expectedSha256 = value;
        break;
      case "--registry-base-url":
        options.registryBaseUrl = value;
        break;
      case "--timeout-ms":
        options.timeoutMs = Number(value);
        break;
      default:
        throw new Error(`Unknown option: ${flag}.`);
    }
    index += 1;
  }
  requiredPath(options.metadataPath, "Metadata");
  requiredPath(options.cratePath, "Crate");
  return options;
}

export const CLI_USAGE = `Usage: node scripts/public/publish-qualified-crate.mjs \\
  --metadata-file FILE --crate-file FILE [options]

Options:
  --expected-sha256 HEX       Verify the existing crate before network access
  --registry-base-url URL     Registry base URL (default: https://crates.io)
  --timeout-ms MILLISECONDS   Bounded request timeout (default: 30000)

The CARGO_REGISTRY_TOKEN environment variable supplies the Authorization header unchanged.`;

export async function main(argv = process.argv.slice(2)) {
  const options = parseCliArgs(argv);
  if (options.help) {
    process.stdout.write(`${CLI_USAGE}\n`);
    return;
  }
  const result = await publishQualifiedCrate(options);
  process.stdout.write(`${JSON.stringify(result.response)}\n`);
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === currentFile) {
  main().catch((error) => {
    process.stderr.write(`publish-qualified-crate: ${error.message}\n`);
    process.exitCode = 1;
  });
}
