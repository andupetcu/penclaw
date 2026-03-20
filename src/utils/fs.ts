import { promises as fs } from "node:fs";
import path from "node:path";

export async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

export async function ensureDirectory(targetPath: string): Promise<void> {
  const directory = path.extname(targetPath) ? path.dirname(targetPath) : targetPath;
  await fs.mkdir(directory, { recursive: true });
}

export async function readTextFile(targetPath: string): Promise<string | null> {
  try {
    return await fs.readFile(targetPath, "utf8");
  } catch {
    return null;
  }
}

export async function writeTextFile(targetPath: string, contents: string): Promise<void> {
  await ensureDirectory(targetPath);
  await fs.writeFile(targetPath, contents, "utf8");
}
