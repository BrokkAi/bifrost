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

function inspectUsesLine(line) {
  const uses = line.match(/^\s*(?:-\s+)?uses:\s*(.*?)\s*$/u);
  if (!uses) {
    return null;
  }

  const reference = uses[1].match(/^(\S+?)(?:\s+#\s*(\S+))?$/u);
  if (!reference) {
    return {
      error: "expected one action reference and an optional single-token ref comment",
    };
  }

  const [, target, comment] = reference;
  if (target.startsWith("./")) {
    return null;
  }

  const separator = target.lastIndexOf("@");
  const commit = separator === -1 ? "" : target.slice(separator + 1);
  if (!FULL_COMMIT.test(commit)) {
    return {
      error: "external actions must use a lowercase 40-character commit SHA",
    };
  }
  if (!comment || !READABLE_REF.test(comment)) {
    return {
      error:
        'external actions must include a readable upstream ref comment such as "# v5.1.0"',
    };
  }

  const [owner, repositoryName] = target.slice(0, separator).split("/");
  if (!owner || !repositoryName) {
    return { error: "external actions must identify an owner and repository" };
  }

  return {
    repository: `${owner}/${repositoryName}`.toLowerCase(),
    pin: `${commit} # ${comment}`,
  };
}

export function validateUsesLine(line) {
  return inspectUsesLine(line)?.error ?? null;
}

export function findUsesPolicyFailures(workflows) {
  const failures = [];
  const repositoryPins = new Map();

  for (const workflow of workflows) {
    const lines = workflow.contents.split(/\r?\n/u);
    lines.forEach((line, index) => {
      const result = inspectUsesLine(line);
      if (!result) {
        return;
      }

      const location = `${workflow.path}:${index + 1}`;
      if (result.error) {
        failures.push(`${location}: ${result.error}`);
        return;
      }

      const previous = repositoryPins.get(result.repository);
      if (previous && previous.pin !== result.pin) {
        failures.push(
          `${location}: ${result.repository} uses ${result.pin}, but ${previous.location} uses ${previous.pin}; one repository must use one SHA/comment tuple`,
        );
        return;
      }
      repositoryPins.set(result.repository, { pin: result.pin, location });
    });
  }

  return failures;
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

test("rejects inconsistent pins from the same action repository", () => {
  const failures = findUsesPolicyFailures([
    {
      path: "first.yml",
      contents:
        "- uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v5.1.0",
    },
    {
      path: "second.yml",
      contents:
        "- uses: Actions/Checkout@1123456789abcdef0123456789abcdef01234567 # v5.2.0",
    },
  ]);

  assert.equal(failures.length, 1);
  assert.match(failures[0], /one repository must use one SHA\/comment tuple/u);
});

test("all checked-in external actions have reviewable immutable refs", () => {
  const workflows = readdirSync(WORKFLOWS_DIRECTORY)
    .filter((file) => [".yaml", ".yml"].includes(extname(file)))
    .sort()
    .map((workflow) => {
      const path = join(WORKFLOWS_DIRECTORY, workflow);
      return {
        path: relative(REPOSITORY_ROOT, path),
        contents: readFileSync(path, "utf8"),
      };
    });

  assert.deepEqual(findUsesPolicyFailures(workflows), []);
});
