import type { RawFinding, ScanCounts, Severity } from "../types/index.js";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function normalizeSeverity(input: string | undefined): Severity {
  const normalized = input?.toLowerCase() ?? "info";
  return severityOrder.includes(normalized as Severity) ? (normalized as Severity) : "info";
}

export function createEmptyCounts(): ScanCounts {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
}

export function countFindings(findings: RawFinding[]): ScanCounts {
  return findings.reduce((counts, finding) => {
    counts[finding.severity] += 1;
    return counts;
  }, createEmptyCounts());
}

export function severityWeight(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}
