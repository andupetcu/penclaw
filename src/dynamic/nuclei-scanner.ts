import type { PenClawConfig, RawFinding, ScannerResult } from "../types/index.js";
import { commandExists, runCommand } from "../utils/process.js";
import { normalizeSeverity } from "../utils/severity.js";

interface NucleiResult {
  "template-id"?: string;
  info?: {
    name?: string;
    description?: string;
    severity?: string;
    reference?: string[];
    tags?: string[];
  };
  "matched-at"?: string;
  "matcher-name"?: string;
  "extracted-results"?: string[];
  host?: string;
  type?: string;
  timestamp?: string;
}

export async function runNucleiScan(targetUrl: string, config: PenClawConfig): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];

  if (!(await commandExists("nuclei"))) {
    warnings.push("Nuclei not installed; skipping web vulnerability template scanning. Install: brew install nuclei");
    return emptyResult(startedAt, warnings);
  }

  try {
    const args = [
      "-u", targetUrl,
      "-jsonl",
      "-silent",
      "-severity", "info,low,medium,high,critical",
      "-type", "http",
      "-disable-update-check",
    ];

    for (const excludePath of config.scan?.excludeVulns ?? []) {
      args.push("-exclude-id", excludePath);
    }

    const { stdout, stderr } = await runCommand("nuclei", args, process.cwd(), 600_000);
    if (stderr.trim()) {
      warnings.push(`Nuclei: ${stderr.trim().split("\n")[0]}`);
    }

    const findings = parseNucleiOutput(stdout);
    return {
      scanner: "nuclei",
      findings,
      warnings,
      executionMs: Date.now() - startedAt,
    };
  } catch (error) {
    warnings.push(`Nuclei scan failed: ${getErrorMessage(error)}`);
    return emptyResult(startedAt, warnings);
  }
}

function parseNucleiOutput(stdout: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const lines = stdout.trim().split("\n").filter(Boolean);

  for (const line of lines) {
    try {
      const result = JSON.parse(line) as NucleiResult;
      findings.push({
        id: `nuclei-${result["template-id"] ?? "unknown"}-${findings.length}`,
        source: "nuclei",
        ruleId: result["template-id"] ?? "unknown",
        title: result.info?.name ?? result["template-id"] ?? "Nuclei finding",
        description: result.info?.description ?? `Nuclei template ${result["template-id"]} matched.`,
        severity: normalizeSeverity(result.info?.severity),
        category: categorizeNucleiResult(result),
        locations: [{
          path: result["matched-at"] ?? result.host ?? "unknown",
          snippet: result["extracted-results"]?.[0],
        }],
        references: result.info?.reference ?? [],
        metadata: {
          tags: result.info?.tags,
          matcherName: result["matcher-name"],
          type: result.type,
        },
      });
    } catch {
      // Skip malformed JSON lines
    }
  }

  return findings;
}

function categorizeNucleiResult(result: NucleiResult): string {
  const tags = result.info?.tags ?? [];
  const tagStr = tags.join(",").toLowerCase();
  if (tagStr.includes("xss")) return "xss";
  if (tagStr.includes("sqli") || tagStr.includes("injection")) return "injection";
  if (tagStr.includes("cve")) return "dependency";
  if (tagStr.includes("exposure") || tagStr.includes("disclosure")) return "information-disclosure";
  if (tagStr.includes("misconfig")) return "misconfiguration";
  if (tagStr.includes("default-login") || tagStr.includes("default-credential")) return "default-credentials";
  return "web-vulnerability";
}

function emptyResult(startedAt: number, warnings: string[]): ScannerResult {
  return { scanner: "nuclei", findings: [], warnings, executionMs: Date.now() - startedAt };
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
