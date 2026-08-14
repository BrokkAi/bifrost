import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Type, type Static } from "typebox";
import { Value } from "typebox/value";

import {
  BIFROST_CAPABILITY_IDS,
  normalizeCapabilities,
  type BifrostCapability,
} from "./bifrost-capabilities.ts";

const BifrostSettingsEnvelope = Type.Object(
  {
    version: Type.Literal(1),
    workspace: Type.String(),
    capabilities: Type.Array(Type.String()),
  },
  { additionalProperties: false },
);

type BifrostSettingsEnvelope = Static<typeof BifrostSettingsEnvelope>;

interface BifrostSettingsDocument {
  version: 1;
  workspace: string;
  capabilities: BifrostCapability[];
}

export interface BifrostSettingsStore {
  load(workspace: string): Promise<BifrostCapability[] | undefined>;
  save(workspace: string, capabilities: readonly BifrostCapability[]): Promise<void>;
}

export function createBifrostSettingsStore(settingsDirectory: string): BifrostSettingsStore {
  const location = async (workspace: string) => {
    const canonicalWorkspace = await realpath(workspace);
    const key = createHash("sha256").update(canonicalWorkspace).digest("hex");
    return {
      canonicalWorkspace,
      settingsPath: join(settingsDirectory, `${key}.json`),
    };
  };

  return {
    async load(workspace) {
      const { canonicalWorkspace, settingsPath } = await location(workspace);
      let source: string;
      try {
        source = await readFile(settingsPath, "utf8");
      } catch (error) {
        if (isMissingFile(error)) {
          return undefined;
        }
        throw error;
      }
      return parseSettingsDocument(source, canonicalWorkspace).capabilities;
    },
    async save(workspace, capabilities) {
      const { canonicalWorkspace, settingsPath } = await location(workspace);
      const document: BifrostSettingsDocument = {
        version: 1,
        workspace: canonicalWorkspace,
        capabilities: normalizeCapabilities(capabilities),
      };
      await mkdir(settingsDirectory, { recursive: true });
      const temporaryPath = join(settingsDirectory, `.${randomUUID()}.tmp`);
      try {
        await writeFile(temporaryPath, `${JSON.stringify(document, null, 2)}\n`, {
          encoding: "utf8",
          mode: 0o600,
        });
        await rename(temporaryPath, settingsPath);
      } finally {
        await rm(temporaryPath, { force: true });
      }
    },
  };
}

export function parseSettingsDocument(
  source: string,
  expectedWorkspace?: string,
): BifrostSettingsDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new Error("Bifrost settings are not valid JSON.", { cause: error });
  }

  let envelope: BifrostSettingsEnvelope;
  try {
    envelope = Value.Parse(BifrostSettingsEnvelope, parsed);
  } catch (error) {
    throw new Error(
      "Bifrost settings must contain version 1, a workspace, and a capabilities array.",
      { cause: error },
    );
  }

  if (expectedWorkspace !== undefined && envelope.workspace !== expectedWorkspace) {
    throw new Error("Bifrost settings do not match the requested workspace.");
  }

  const knownCapabilities = new Set<string>(BIFROST_CAPABILITY_IDS);
  const unknown = envelope.capabilities.filter((item) => !knownCapabilities.has(item));
  if (unknown.length > 0) {
    throw new Error(`Bifrost settings contain unknown capabilities: ${unknown.join(", ")}.`);
  }

  return {
    version: 1,
    workspace: envelope.workspace,
    capabilities: normalizeCapabilities(envelope.capabilities),
  };
}

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}
