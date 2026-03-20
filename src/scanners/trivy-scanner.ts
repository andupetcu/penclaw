import path from "node:path";
import type { PenClawConfig, RawFinding, ScannerResult } from "../types/index.js";
import { commandExists, runCommand } from "../utils/process.js";
import { normalizeSeverity } from "../utils/severity.js";

interface TrivyResult {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID?: string;
      Title?: string;
      Description?: string;
      Severity?: string;
      PrimaryURL?: string;
      PkgName?: string;
      InstalledVersion?: string;
    }>;
    Secrets?: Array<{
      RuleID?: string;
      Title?: string;
      Severity?: string;
      StartLine?: number;
      EndLine?: number;
      Match?: string;
    }>;
    Misconfigurations?: Array<{
      ID?: string;
      Title?: string;
      Description?: string;
      Severity?: string;
      PrimaryURL?: string;
    }>;
  }>;
}

export async function runTrivyScan(targetPath: string, config: PenClawConfig): Promise<ScannerResult> {
  const startedAt = Date.now();
  const warnings: string[] = [];

  if (!(await commandExists("trivy"))) {
    warnings.push("Trivy not installed; skipping filesystem dependency scan.");
    return emptyResult(startedAt, warnings);
  }

  try {
    const args = [
      "fs",
      "--scanners",
      "vuln,secret,misconfig",
      "--format",
      "json",
      "--quiet",
      targetPath,
    ];

    if (config.scan?.excludePaths?.length) {
      for (const excludePath of config.scan.excludePaths) {
        args.push("--skip-dirs", excludePath);
      }
    }

    const { stdout, stderr } = await runCommand("trivy", args, path.dirname(targetPath));
    if (stderr.trim().length > 0) {
      warnings.push(stderr.trim());
    }

    const parsed = JSON.parse(stdout) as TrivyResult;
    return {
      scanner: "trivy",
      findings: parseTrivyFindings(parsed),
      warnings,
      executionMs: Date.now() - startedAt,
    };
  } catch (error) {
    warnings.push(`Trivy scan failed: ${getErrorMessage(error)}`);
    return emptyResult(startedAt, warnings);
  }
}

function parseTrivyFindings(result: TrivyResult): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const entry of result.Results ?? []) {
    const target = entry.Target ?? "unknown";

    for (const vulnerability of entry.Vulnerabilities ?? []) {
      findings.push({
        id: `trivy-${vulnerability.VulnerabilityID ?? vulnerability.Title ?? findings.length}`,
        source: "trivy",
        ruleId: vulnerability.VulnerabilityID ?? "unknown",
        title: vulnerability.Title ?? vulnerability.VulnerabilityID ?? "Dependency vulnerability",
        description: vulnerability.Description ?? "Dependency vulnerability discovered by Trivy.",
        severity: normalizeSeverity(vulnerability.Severity),
        category: "dependency",
        locations: [{ path: target }],
        references: vulnerability.PrimaryURL ? [vulnerability.PrimaryURL] : [],
        metadata: {
          packageName: vulnerability.PkgName,
          installedVersion: vulnerability.InstalledVersion,
        },
      });
    }

    for (const secret of entry.Secrets ?? []) {
      findings.push({
        id: `trivy-secret-${secret.RuleID ?? findings.length}`,
        source: "trivy",
        ruleId: secret.RuleID ?? "trivy-secret",
        title: secret.Title ?? "Potential secret exposed",
        description: "Trivy identified a secret-like value in the repository.",
        severity: normalizeSeverity(secret.Severity),
        category: "secret",
        locations: [{ path: target, line: secret.StartLine, snippet: secret.Match }],
        metadata: {
          endLine: secret.EndLine,
        },
      });
    }

    for (const misconfiguration of entry.Misconfigurations ?? []) {
      findings.push({
        id: `trivy-misconfig-${misconfiguration.ID ?? findings.length}`,
        source: "trivy",
        ruleId: misconfiguration.ID ?? "trivy-misconfig",
        title: misconfiguration.Title ?? "Misconfiguration detected",
        description: misconfiguration.Description ?? "Trivy identified a misconfiguration.",
        severity: normalizeSeverity(misconfiguration.Severity),
        category: "misconfiguration",
        locations: [{ path: target }],
        references: misconfiguration.PrimaryURL ? [misconfiguration.PrimaryURL] : [],
      });
    }
  }

  return findings;
}

function emptyResult(startedAt: number, warnings: string[]): ScannerResult {
  return {
    scanner: "trivy",
    findings: [],
    warnings,
    executionMs: Date.now() - startedAt,
  };
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
