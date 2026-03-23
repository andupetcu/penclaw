import type { SarifReport, SarifResult, SarifRule, ScanReport, TriageFinding } from "../types/index.js";

export function renderSarifReport(report: ScanReport): string {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleIndex = new Map<string, number>();

  for (const finding of report.findings) {
    let index = ruleIndex.get(finding.ruleId);
    if (index === undefined) {
      index = rules.length;
      ruleIndex.set(finding.ruleId, index);
      rules.push({
        id: finding.ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        defaultConfiguration: { level: severityToLevel(finding) },
        helpUri: finding.references?.[0],
      });
    }

    results.push({
      ruleId: finding.ruleId,
      ruleIndex: index,
      level: severityToLevel(finding),
      message: { text: buildMessage(finding) },
      locations: finding.locations.map((loc) => ({
        physicalLocation: {
          artifactLocation: { uri: loc.path },
          region: loc.line ? { startLine: loc.line, startColumn: loc.column } : undefined,
        },
      })),
    });
  }

  const sarif: SarifReport = {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: report.tool.name,
            version: report.tool.version,
            informationUri: "https://github.com/anthropics/penclaw",
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function severityToLevel(finding: TriageFinding): "error" | "warning" | "note" | "none" {
  switch (finding.severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "none";
  }
}

function buildMessage(finding: TriageFinding): string {
  const parts = [finding.description];
  if (finding.reasoning) parts.push(`Triage: ${finding.reasoning}`);
  if (finding.fixSuggestion) parts.push(`Fix: ${finding.fixSuggestion}`);
  return parts.join("\n\n");
}
