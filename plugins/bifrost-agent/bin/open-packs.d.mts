export interface EnginePackProfile {
  engine_version: string;
  build_identity: string;
  model_set_sha256: string;
  capability_contract_version: number;
  schemas: Record<string, number[]>;
  capabilities: string[];
}

export interface OpenPackReceipt {
  receipt_schema_version: 1 | 2;
  status: "qualified" | "compatible";
  selection_id: string;
  engine_profile: EnginePackProfile;
  inventory_fetched_at: string;
  discovery_status: "online" | "fresh-cache" | "offline-cache" | "stale-cache";
  cache_reused: boolean;
  path: string;
  releases: Array<Record<string, unknown>>;
  verified_contents: Record<string, Array<{ path: string; sha256: string }>>;
  extracted_files: Record<string, Array<{ path: string; size_bytes: number; sha256: string }>>;
  artifacts: Array<Record<string, unknown>>;
}

export interface PreparedOpenPacks {
  env: Record<string, string>;
  receipt: OpenPackReceipt;
}

export class OpenPackError extends Error {
  code: string;
  details?: unknown;
}

export function openPackCacheRootFor(
  env?: NodeJS.ProcessEnv,
  platform?: NodeJS.Platform,
  homedir?: string
): string;

export function readEnginePackProfile(
  binaryPath: string,
  options?: { execFileImpl?: (...args: any[]) => Promise<any>; env?: NodeJS.ProcessEnv }
): Promise<EnginePackProfile>;

export function prepareOpenPacks(options: {
  cacheDir: string;
  engineProfile: EnginePackProfile;
  fetchImpl?: typeof fetch;
  offline?: boolean;
  refresh?: boolean;
}): Promise<PreparedOpenPacks>;
