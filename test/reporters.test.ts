import { describe, it, expect } from "vitest";
import type { ScanReport, TriageFinding } from "../src/types/index.js";
import { renderJsonReport } from "../src/reporters/json.js";
import { renderMarkdownReport } from "../src/reporters/markdown.js";

function makeReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    tool: { name: "PenClaw", version: "0.1.0" },
    generatedAt: new Date().toISOString(),
    durationMs: 1234,
    targetProfile: {
      target: "/test",
      type: "filesystem",
      languages: [{ name: "JavaScript", files: 5 }],
      frameworks: ["Express"],
      packageManagers: ["npm"],
      manifests: ["package.json"],
      entryPoints: ["index.js"],
      fileCount: 20,
    },
    findings: [],
    rawFindings: [],
    warnings: [],
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    ...overrides,
  };
}

function makeFinding(overrides: Partial<TriageFinding> = {}): TriageFinding {
  return {
    id: "test-1",
    source: "secrets",
    ruleId: "test-rule",
    title: "Test Secret Found",
    description: "A hardcoded secret was found.",
    severity: "high",
    category: "secret",
    locations: [{ path: "app.js", line: 42, snippet: 'const key = "secret123"' }],
    confidence: 0.85,
    deduplicationKey: "secret:test-rule:app.js:42",
    falsePositiveLikelihood: 0.15,
    reasoning: "Pattern match on known secret format.",
    proofOfConcept: "Check app.js:42 for exposed credential.",
    fixSuggestion: "Move to environment variable.",
    relatedFindings: [],
    ...overrides,
  };
}

describe("JSON reporter", () => {
  it("produces valid JSON", () => {
    const report = makeReport();
    const output = renderJsonReport(report);
    const parsed = JSON.parse(output);
    expect(parsed.tool.name).toBe("PenClaw");
  });

  it("includes findings in JSON output", () => {
    const report = makeReport({
      findings: [makeFinding()],
      counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    });
    const output = renderJsonReport(report);
    const parsed = JSON.parse(output);
    expect(parsed.findings.length).toBe(1);
    expect(parsed.findings[0].severity).toBe("high");
  });

  it("preserves all report fields", () => {
    const report = makeReport({ warnings: ["Scanner X not installed"] });
    const output = renderJsonReport(report);
    const parsed = JSON.parse(output);
    expect(parsed.warnings).toContain("Scanner X not installed");
    expect(parsed.targetProfile.languages[0].name).toBe("JavaScript");
  });
});

describe("Markdown reporter", () => {
  it("produces valid Markdown with header", () => {
    const report = makeReport();
    const output = renderMarkdownReport(report);
    expect(output).toContain("# PenClaw Security Report");
    expect(output).toContain("**Target:**");
    expect(output).toContain("## Summary");
  });

  it("includes findings in Markdown output", () => {
    const report = makeReport({
      findings: [makeFinding()],
      counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    });
    const output = renderMarkdownReport(report);
    expect(output).toContain("### [HIGH] Test Secret Found");
    expect(output).toContain("test-rule");
    expect(output).toContain("Move to environment variable.");
  });

  it("handles empty findings", () => {
    const report = makeReport();
    const output = renderMarkdownReport(report);
    expect(output).toContain("No actionable findings survived triage.");
  });

  it("includes warnings section", () => {
    const report = makeReport({ warnings: ["Trivy not installed"] });
    const output = renderMarkdownReport(report);
    expect(output).toContain("## Warnings");
    expect(output).toContain("Trivy not installed");
  });

  it("includes target profile", () => {
    const report = makeReport();
    const output = renderMarkdownReport(report);
    expect(output).toContain("## Target Profile");
    expect(output).toContain("JavaScript");
    expect(output).toContain("Express");
  });

  it("renders evidence snippet", () => {
    const report = makeReport({
      findings: [makeFinding()],
      counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    });
    const output = renderMarkdownReport(report);
    expect(output).toContain("**Evidence:**");
    expect(output).toContain('const key = "secret123"');
  });
});
