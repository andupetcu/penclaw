import path from "node:path";
import { promises as fs } from "node:fs";
import fg from "fast-glob";
import type { PenClawConfig, RawFinding, ScannerResult, Severity } from "../types/index.js";

const secretPatterns: Array<{ id: string; title: string; pattern: RegExp; severity: Severity }> = [
  {
    id: "aws-access-key",
    title: "AWS access key exposed",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "high",
  },
  {
    id: "github-token",
    title: "GitHub token exposed",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    severity: "high",
  },
  {
    id: "slack-token",
    title: "Slack token exposed",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g,
    severity: "high",
  },
  {
    id: "private-key",
    title: "Private key material exposed",
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    severity: "critical",
  },
  {
    id: "generic-api-key",
    title: "Hardcoded API key detected",
    pattern: /\b(?:api|secret|token|access|private|password)[\w-]{0,20}\b\s*[:=]\s*["'][A-Za-z0-9_\-\/+=]{20,}["']/gi,
    severity: "medium",
  },
];

const textExtensions = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".env",
  ".py",
  ".rb",
  ".go",
  ".java",
  ".kt",
  ".php",
  ".txt",
  ".md",
  ".sh",
  ".zsh",
]);

const defaultIgnores = ["node_modules/**", ".git/**", "dist/**", "build/**", "coverage/**"];

/** Files that contain high-entropy strings by nature (checksums, hashes) — skip entropy scanning */
const entropyIgnoreFiles = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  "Cargo.lock",
  "poetry.lock",
  "go.sum",
  "Pipfile.lock",
  "shrinkwrap.json",
  "npm-shrinkwrap.json",
]);

/** Patterns that look like integrity hashes / checksums, not secrets */
const entropyFalsePositivePatterns = [
  /^sha[0-9]+-/,             // npm integrity hashes: sha512-...
  /^[0-9a-f]{40,128}$/,      // hex hashes (SHA-1, SHA-256, SHA-512)
  /^[A-Za-z0-9+/]{40,}={0,3}$/, // pure base64 blobs without any prefix context
];

export async function runSecretScan(targetPath: string, config: PenClawConfig): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];
  const findings: RawFinding[] = [];

  try {
    const files = await fg(["**/*"], {
      cwd: targetPath,
      dot: true,
      onlyFiles: true,
      ignore: [...defaultIgnores, ...(config.scan?.excludePaths ?? [])],
    });

    for (const file of files) {
      if (!isTextCandidate(file)) {
        continue;
      }

      const absolutePath = path.join(targetPath, file);
      const contents = await fs.readFile(absolutePath, "utf8").catch(() => null);
      if (!contents) {
        continue;
      }

      findings.push(...scanPatterns(file, contents));
      findings.push(...scanHighEntropy(file, contents));
    }
  } catch (error) {
    warnings.push(`Secret scan failed: ${getErrorMessage(error)}`);
  }

  return {
    scanner: "secrets",
    findings,
    warnings,
    executionMs: Date.now() - startedAt,
  };
}

function isTextCandidate(filePath: string): boolean {
  const extension = path.extname(filePath);
  return textExtensions.has(extension) || path.basename(filePath).startsWith(".env");
}

function scanPatterns(filePath: string, contents: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const lines = contents.split(/\r?\n/);

  for (const secretPattern of secretPatterns) {
    secretPattern.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = secretPattern.pattern.exec(contents)) !== null) {
      const line = offsetToLine(contents, match.index);
      findings.push({
        id: `secret-${secretPattern.id}-${filePath}-${match.index}`,
        source: "secrets",
        ruleId: secretPattern.id,
        title: secretPattern.title,
        description: "Potential credential material found in source code or config.",
        severity: secretPattern.severity,
        category: "secret",
        locations: [{ path: filePath, line, snippet: lines[line - 1]?.trim() }],
      });
    }
  }

  return findings;
}

function scanHighEntropy(filePath: string, contents: string): RawFinding[] {
  const fileName = path.basename(filePath);

  // Skip lockfiles entirely — they are full of integrity hashes / checksums
  if (entropyIgnoreFiles.has(fileName)) {
    return [];
  }

  const findings: RawFinding[] = [];
  const lines = contents.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const candidates = line.match(/[A-Za-z0-9+/=_-]{24,}/g) ?? [];
    for (const candidate of candidates) {
      if (candidate.includes("://")) {
        continue;
      }

      // Skip known non-secret high-entropy patterns
      if (isEntropyFalsePositive(candidate, line)) {
        continue;
      }

      const entropy = shannonEntropy(candidate);
      if (entropy >= 4.1) {
        findings.push({
          id: `secret-entropy-${filePath}-${index + 1}-${candidate.slice(0, 12)}`,
          source: "secrets",
          ruleId: "high-entropy-string",
          title: "High entropy secret-like token",
          description: `A string with unusually high entropy may represent a secret or credential (entropy ${entropy.toFixed(2)}).`,
          severity: entropy >= 4.6 ? "high" : "medium",
          category: "secret",
          locations: [{ path: filePath, line: index + 1, snippet: line.trim() }],
          metadata: {
            entropy,
          },
        });
      }
    }
  }

  return findings;
}

function isEntropyFalsePositive(candidate: string, line: string): boolean {
  // Check candidate against known false-positive patterns
  for (const pattern of entropyFalsePositivePatterns) {
    if (pattern.test(candidate)) {
      return true;
    }
  }

  // Lines containing "integrity" keys (e.g. in manifests/lockfiles)
  if (/\bintegrity\b/i.test(line)) {
    return true;
  }

  // Checksum / hash lines in various formats
  if (/\b(?:checksum|sha256|sha512|sha1|hash|digest)\b/i.test(line)) {
    return true;
  }

  return false;
}

function offsetToLine(contents: string, offset: number): number {
  return contents.slice(0, offset).split(/\r?\n/).length;
}

function shannonEntropy(value: string): number {
  const frequency = new Map<string, number>();
  for (const character of value) {
    frequency.set(character, (frequency.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequency.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
