export interface BifrostLaunch {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  source: "explicit" | "managed" | "path" | "installed";
}

export function resolveBifrostLaunch(options: {
  root: string;
  env?: NodeJS.ProcessEnv;
  toolset?: string;
  passThrough?: string[];
}): Promise<BifrostLaunch>;
