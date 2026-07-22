import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const FULL_COMMIT = /^[0-9a-f]{40}$/u;
const READABLE_REF = /^(?![0-9a-f]{40}$)[A-Za-z0-9][A-Za-z0-9._/+_-]*$/u;
const REPOSITORY_ROOT = fileURLToPath(new URL("../", import.meta.url));
const WORKFLOWS_DIRECTORY = fileURLToPath(
  new URL("../.github/workflows/", import.meta.url),
);

export function validateUsesLine(line) {
  const uses = line.match(/^\s*(?:-\s+)?uses:\s*(.*?)\s*$/u);
  if (!uses) {
    return null;
  }

  const reference = uses[1].match(/^(\S+?)(?:\s+#\s*(\S+))?$/u);
  if (!reference) {
    return "expected one action reference and an optional single-token ref comment";
  }

  const [, target, comment] = reference;
  if (target.startsWith("./")) {
    return null;
  }

  const separator = target.lastIndexOf("@");
  const commit = separator === -1 ? "" : target.slice(separator + 1);
  if (!FULL_COMMIT.test(commit)) {
    return "external actions must use a lowercase 40-character commit SHA";
  }
  if (!comment || !READABLE_REF.test(comment)) {
    return 'external actions must include a readable upstream ref comment such as "# v5.1.0"';
  }

  return null;
}

test("rejects a mutable external action ref", () => {
  assert.match(
    validateUsesLine("      - uses: actions/checkout@v5"),
    /40-character commit SHA/u,
  );
});

test("rejects an immutable action ref without a readable comment", () => {
  assert.match(
    validateUsesLine(
      "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567",
    ),
    /readable upstream ref comment/u,
  );
});

test("accepts release and branch comments on immutable action refs", () => {
  assert.equal(
    validateUsesLine(
      "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v5.1.0",
    ),
    null,
  );
  assert.equal(
    validateUsesLine(
      "        uses: dtolnay/rust-toolchain@0123456789abcdef0123456789abcdef01234567 # stable",
    ),
    null,
  );
});

test("ignores local actions and reusable workflows", () => {
  assert.equal(
    validateUsesLine("    uses: ./.github/workflows/release-context.yml"),
    null,
  );
});

test("all checked-in external actions have reviewable immutable refs", () => {
  const failures = [];
  const workflows = readdirSync(WORKFLOWS_DIRECTORY)
    .filter((file) => [".yaml", ".yml"].includes(extname(file)))
    .sort();

  for (const workflow of workflows) {
    const path = join(WORKFLOWS_DIRECTORY, workflow);
    const lines = readFileSync(path, "utf8").split(/\r?\n/u);
    lines.forEach((line, index) => {
      const error = validateUsesLine(line);
      if (error) {
        failures.push(`${relative(REPOSITORY_ROOT, path)}:${index + 1}: ${error}`);
      }
    });
  }

  assert.deepEqual(failures, []);
});
