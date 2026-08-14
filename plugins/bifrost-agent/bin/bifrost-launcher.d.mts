export interface BifrostLaunch {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  source: "explicit" | "managed" | "path" | "installed";
  preferredVersion: string;
  selectedVersion: string;
  compatibilityMode: "exact" | "compatible";
}

export function resolveBifrostLaunch(options: {
  root: string;
  env?: NodeJS.ProcessEnv;
  toolset?: string;
  passThrough?: string[];
}): Promise<BifrostLaunch>;

export function resolveBifrostLspLaunch(options: {
  root: string;
  env?: NodeJS.ProcessEnv;
  passThrough?: string[];
}): Promise<BifrostLaunch>;
