import path from "node:path";
import { cosmiconfig } from "cosmiconfig";
import type { PenClawConfig } from "../types/index.js";

export async function loadConfig(searchFrom: string, configPath?: string): Promise<PenClawConfig> {
  const explorer = cosmiconfig("penclaw");
  const result = configPath
    ? await explorer.load(path.resolve(searchFrom, configPath))
    : await explorer.search(searchFrom);

  return (result?.config as PenClawConfig | undefined) ?? {};
}
