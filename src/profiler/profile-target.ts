import path from "node:path";
import fg from "fast-glob";
import ignore from "ignore";
import type { DetectedLanguage, PenClawConfig, TargetProfile } from "../types/index.js";
import { pathExists, readTextFile } from "../utils/fs.js";

const languageMap: Array<{ name: string; patterns: string[] }> = [
  { name: "TypeScript", patterns: ["**/*.ts", "**/*.tsx"] },
  { name: "JavaScript", patterns: ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"] },
  { name: "Python", patterns: ["**/*.py"] },
  { name: "Go", patterns: ["**/*.go"] },
  { name: "Ruby", patterns: ["**/*.rb"] },
  { name: "PHP", patterns: ["**/*.php"] },
  { name: "Java", patterns: ["**/*.java"] },
  { name: "Rust", patterns: ["**/*.rs"] },
];

const frameworkHints: Array<{ name: string; files: string[]; content?: RegExp }> = [
  { name: "Next.js", files: ["next.config.js", "next.config.mjs", "next.config.ts"] },
  { name: "Express", files: ["package.json"], content: /"express"\s*:/ },
  { name: "NestJS", files: ["package.json"], content: /"@nestjs\/core"\s*:/ },
  { name: "React", files: ["package.json"], content: /"react"\s*:/ },
  { name: "Vue", files: ["package.json"], content: /"vue"\s*:/ },
  { name: "Django", files: ["manage.py", "pyproject.toml", "requirements.txt"], content: /django/i },
  { name: "Flask", files: ["pyproject.toml", "requirements.txt"], content: /flask/i },
  { name: "FastAPI", files: ["pyproject.toml", "requirements.txt"], content: /fastapi/i },
];

const packageManagerFiles = [
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "go.sum",
  "Cargo.lock",
];

const defaultIgnores = ["node_modules/**", ".git/**", "dist/**", "build/**", "coverage/**"];

export async function profileTarget(targetPath: string, config: PenClawConfig): Promise<TargetProfile> {
  const resolvedTarget = path.resolve(targetPath);
  if (!(await pathExists(resolvedTarget))) {
    throw new Error(`Target path does not exist: ${resolvedTarget}`);
  }

  const customIgnores = config.scan?.excludePaths ?? [];
  const ig = ignore().add(customIgnores);
  const entries = await fg(["**/*"], {
    cwd: resolvedTarget,
    dot: true,
    onlyFiles: true,
    ignore: [...defaultIgnores, ...customIgnores],
    unique: true,
  });

  const filteredEntries = entries.filter((entry) => !ig.ignores(entry));
  const languages = await detectLanguages(resolvedTarget, filteredEntries);
  const frameworks = await detectFrameworks(resolvedTarget);
  const packageManagers = packageManagerFiles.filter((file) => filteredEntries.includes(file));
  const manifests = filteredEntries.filter((file) =>
    ["package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml"].includes(path.basename(file)),
  );
  const entryPoints = filteredEntries.filter((file) =>
    /(^|\/)(index|main|app|server)\.(ts|tsx|js|jsx|py|go)$/i.test(file),
  );

  return {
    target: resolvedTarget,
    type: "filesystem",
    languages,
    frameworks,
    packageManagers,
    manifests,
    entryPoints,
    fileCount: filteredEntries.length,
  };
}

async function detectLanguages(root: string, entries: string[]): Promise<DetectedLanguage[]> {
  const counts = new Map<string, number>();

  for (const language of languageMap) {
    const matches = await fg(language.patterns, {
      cwd: root,
      onlyFiles: true,
      ignore: defaultIgnores,
    });
    if (matches.length > 0) {
      counts.set(language.name, matches.length);
    }
  }

  if (counts.size === 0 && entries.length > 0) {
    counts.set("Unknown", entries.length);
  }

  return [...counts.entries()]
    .map(([name, files]) => ({ name, files }))
    .sort((left, right) => right.files - left.files);
}

async function detectFrameworks(root: string): Promise<string[]> {
  const frameworks = new Set<string>();

  for (const hint of frameworkHints) {
    for (const file of hint.files) {
      const contents = await readTextFile(path.join(root, file));
      if (!contents) {
        continue;
      }

      if (!hint.content || hint.content.test(contents)) {
        frameworks.add(hint.name);
      }
    }
  }

  return [...frameworks];
}
