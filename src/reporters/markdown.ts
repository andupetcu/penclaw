import type { ScanReport, TriageFinding } from "../types/index.js";

export function renderMarkdownReport(report: ScanReport): string {
  const lines: string[] = [];
  lines.push("# PenClaw Security Report");
  lines.push(`**Target:** \`${report.targetProfile.target}\``);
  lines.push(`**Date:** ${report.generatedAt}`);
  lines.push(`**Duration:** ${formatDuration(report.durationMs)}`);
  lines.push("");
  lines.push("## Summary");
  lines.push(`- Critical: ${report.counts.critical}`);
  lines.push(`- High: ${report.counts.high}`);
  lines.push(`- Medium: ${report.counts.medium}`);
  lines.push(`- Low: ${report.counts.low}`);
  lines.push(`- Informational: ${report.counts.info}`);
  lines.push("");
  lines.push("## Target Profile");
  lines.push(`- Languages: ${report.targetProfile.languages.map((language) => `${language.name} (${language.files})`).join(", ") || "Unknown"}`);
  lines.push(`- Frameworks: ${report.targetProfile.frameworks.join(", ") || "None detected"}`);
  lines.push(`- Package managers: ${report.targetProfile.packageManagers.join(", ") || "None detected"}`);
  lines.push(`- Files analyzed: ${report.targetProfile.fileCount}`);
  lines.push("");

  if (report.findings.length === 0) {
    lines.push("## Findings");
    lines.push("No actionable findings survived triage.");
  } else {
    lines.push("## Findings");
    for (const finding of report.findings) {
      lines.push(renderFinding(finding));
    }
  }

  if (report.warnings.length > 0) {
    lines.push("");
    lines.push("## Warnings");
    for (const warning of report.warnings) {
      lines.push(`- ${warning}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}

function renderFinding(finding: TriageFinding): string {
  const location = finding.locations[0];
  const sections = [
    `### [${finding.severity.toUpperCase()}] ${finding.title}`,
    `**Rule:** \`${finding.ruleId}\``,
    `**Source:** ${finding.source}`,
    `**Location:** \`${location?.path ?? "unknown"}${location?.line ? `:${location.line}` : ""}\``,
    `**Confidence:** ${Math.round(finding.confidence * 100)}%`,
    "",
    `**Description:** ${finding.description}`,
    "",
    `**Triage:** ${finding.reasoning}`,
    "",
    "**Proof of Concept:**",
    "```text",
    finding.proofOfConcept,
    "```",
    "",
    "**Fix Suggestion:**",
    "```text",
    finding.fixSuggestion,
    "```",
  ];

  if (location?.snippet) {
    sections.push("", "**Evidence:**", "```text", location.snippet, "```");
  }

  return sections.join("\n");
}

function formatDuration(durationMs: number): string {
  const seconds = Math.round(durationMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return minutes > 0 ? `${minutes}m ${remainingSeconds}s` : `${remainingSeconds}s`;
}
