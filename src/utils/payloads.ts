import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Payload } from "../types/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const payloadsDir = resolve(__dirname, "../../data/payloads");

const cache = new Map<string, Payload[]>();

export function loadPayloads(category: string): Payload[] {
  const cached = cache.get(category);
  if (cached) return cached;

  const filePath = resolve(payloadsDir, `${category}.json`);
  const raw = JSON.parse(readFileSync(filePath, "utf-8")) as unknown[];

  const payloads: Payload[] = raw.map((entry) => {
    const e = entry as Record<string, unknown>;
    return {
      value: String(e.value ?? e),
      technique: String(e.technique ?? "unknown"),
      description: String(e.description ?? ""),
      ...(e.dbms ? { dbms: String(e.dbms) } : {}),
      ...(e.context ? { context: String(e.context) } : {}),
    };
  });

  cache.set(category, payloads);
  return payloads;
}

export function loadDirectoryPaths(): string[] {
  const filePath = resolve(payloadsDir, "directories.json");
  return JSON.parse(readFileSync(filePath, "utf-8")) as string[];
}
