import path from "node:path";
import type { PenClawConfig, RawFinding, ScannerResult } from "../types/index.js";
import { commandExists, runCommand } from "../utils/process.js";
import { normalizeSeverity } from "../utils/severity.js";

interface SemgrepResult {
  results?: Array<{
    check_id: string;
    path: string;
    start?: { line?: number; col?: number };
    extra?: {
      message?: string;
      lines?: string;
      severity?: string;
      metadata?: {
        category?: string;
        confidence?: string;
        references?: string[];
      };
    };
  }>;
  errors?: Array<{ message: string }>;
}

export async function runSemgrepScan(targetPath: string, config: PenClawConfig): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];

  if (!(await commandExists("semgrep"))) {
    warnings.push("Semgrep not installed; skipping rule-based code scanning.");
    return emptyResult(startedAt, warnings);
  }

  try {
    const args = [
      "scan",
      "--config",
      "p/security-audit",
      "--json",
      "--quiet",
      "--error",
      "--metrics=off",
      targetPath,
    ];

    if (config.scan?.customRules) {
      args.splice(2, 0, "--config", config.scan.customRules);
    }

    for (const excludePath of config.scan?.excludePaths ?? []) {
      args.push("--exclude", excludePath);
    }

    const { stdout } = await runCommand("semgrep", args, path.dirname(targetPath));
    const parsed = JSON.parse(stdout) as SemgrepResult;
    warnings.push(...(parsed.errors ?? []).map((error) => `Semgrep: ${error.message}`));

    return {
      scanner: "semgrep",
      findings: parseSemgrepFindings(parsed),
      warnings,
      executionMs: Date.now() - startedAt,
    };
  } catch (error) {
    warnings.push(`Semgrep scan failed: ${getErrorMessage(error)}`);
    return emptyResult(startedAt, warnings);
  }
}

function parseSemgrepFindings(result: SemgrepResult): RawFinding[] {
  return (result.results ?? []).map((finding, index) => ({
    id: `semgrep-${finding.check_id}-${index}`,
    source: "semgrep",
    ruleId: finding.check_id,
    title: finding.extra?.message ?? finding.check_id,
    description: finding.extra?.message ?? "Semgrep identified a potential security issue.",
    severity: normalizeSeverity(finding.extra?.severity),
    category: finding.extra?.metadata?.category ?? "code",
    locations: [
      {
        path: finding.path,
        line: finding.start?.line,
        column: finding.start?.col,
        snippet: finding.extra?.lines,
      },
    ],
    references: finding.extra?.metadata?.references ?? [],
    metadata: {
      confidence: finding.extra?.metadata?.confidence,
    },
  }));
}

function emptyResult(startedAt: number, warnings: string[]): ScannerResult {
  return {
    scanner: "semgrep",
    findings: [],
    warnings,
    executionMs: Date.now() - startedAt,
  };
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
